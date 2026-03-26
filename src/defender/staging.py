"""Staging evaluation pipeline — defense layers must prove themselves before production.

No defense layer goes directly to production. Every new or regenerated layer
passes through a multi-stage evaluation pipeline:

    shadow → canary → staged_rollout → production

Architecture (Part 3 — Claude Code CLI Management/CI-CD):
- **Shadow**: Layer runs in parallel but results are ignored (only logged)
- **Canary**: Layer runs on 10% of traffic alongside production layers
- **Staged rollout**: Layer runs on 50% of traffic, gradually increasing
- **Production**: Layer is fully active in the defense pipeline

Each stage has minimum time and test run requirements. Layers that fail
to meet promotion thresholds are rejected and sent back for regeneration.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta

from src.db.models import StagingRecord
from src.db.result_store import ResultStore
from src.utils.logging import get_logger

logger = get_logger()

_STAGES = ["shadow", "canary", "staged_rollout", "production"]

_STAGE_CONFIG = {
    "shadow": {
        "min_hours": 24,
        "min_test_runs": 10,
        "traffic_pct": 0,      # 0% — results not used for blocking
        "promotion_threshold": 0.5,
        "rejection_threshold": 0.2,
    },
    "canary": {
        "min_hours": 12,
        "min_test_runs": 20,
        "traffic_pct": 10,
        "promotion_threshold": 0.6,
        "rejection_threshold": 0.25,
    },
    "staged_rollout": {
        "min_hours": 24,
        "min_test_runs": 30,
        "traffic_pct": 50,
        "promotion_threshold": 0.7,
        "rejection_threshold": 0.3,
    },
    "production": {
        "min_hours": 0,
        "min_test_runs": 0,
        "traffic_pct": 100,
        "promotion_threshold": 0.0,
        "rejection_threshold": 0.0,
    },
}


class StagingPipeline:
    """Manages the staged evaluation of new defense layers.

    Ensures no untested or underperforming layer reaches production.
    Each layer must pass through shadow → canary → staged_rollout → production,
    meeting minimum test run counts and effectiveness thresholds at each stage.
    """

    def __init__(
        self,
        result_store: ResultStore,
        config: dict | None = None,
    ) -> None:
        self.result_store = result_store
        self.session = result_store.session
        self.config = config or {}

        # Allow config overrides for stage timing
        staging_config = self.config.get("robustness", {}).get("staging", {})
        for stage_name, overrides in staging_config.items():
            if stage_name in _STAGE_CONFIG:
                _STAGE_CONFIG[stage_name].update(overrides)

    def enter_staging(self, layer_name: str) -> StagingRecord:
        """Place a new defense layer into shadow stage.

        Returns the created StagingRecord.
        """
        # Check if already in staging
        existing = (
            self.session.query(StagingRecord)
            .filter_by(layer_name=layer_name, promoted=False, rejected=False)
            .first()
        )
        if existing:
            logger.info(
                "Layer already in staging",
                extra={"extra_data": {
                    "layer": layer_name,
                    "stage": existing.stage,
                }},
            )
            return existing

        stage_config = _STAGE_CONFIG["shadow"]
        record = StagingRecord(
            id=str(uuid.uuid4()),
            layer_name=layer_name,
            stage="shadow",
            min_evaluation_hours=stage_config["min_hours"],
            test_runs_required=stage_config["min_test_runs"],
            promotion_threshold=stage_config["promotion_threshold"],
            rejection_threshold=stage_config["rejection_threshold"],
        )
        self.session.add(record)
        self.session.commit()

        logger.info(
            "Layer entered staging",
            extra={"extra_data": {
                "layer": layer_name,
                "stage": "shadow",
                "min_hours": stage_config["min_hours"],
                "min_runs": stage_config["min_test_runs"],
            }},
        )
        return record

    def record_test_result(
        self, layer_name: str, detection_rate: float, false_positive_rate: float,
    ) -> None:
        """Record a test result for a layer currently in staging."""
        record = (
            self.session.query(StagingRecord)
            .filter_by(layer_name=layer_name, promoted=False, rejected=False)
            .first()
        )
        if not record:
            return

        # Running average
        n = record.test_runs_completed
        record.detection_rate_avg = (
            (record.detection_rate_avg * n + detection_rate) / (n + 1)
        )
        record.false_positive_rate_avg = (
            (record.false_positive_rate_avg * n + false_positive_rate) / (n + 1)
        )
        record.test_runs_completed = n + 1
        self.session.commit()

    def evaluate_promotions(self) -> dict:
        """Evaluate all staging layers for promotion or rejection.

        Returns a dict with lists of promoted, rejected, and unchanged layers.
        """
        active_records = (
            self.session.query(StagingRecord)
            .filter_by(promoted=False, rejected=False)
            .all()
        )

        promoted = []
        rejected = []
        unchanged = []

        now = datetime.now(timezone.utc)

        for record in active_records:
            stage_config = _STAGE_CONFIG.get(record.stage, {})
            min_hours = stage_config.get("min_hours", record.min_evaluation_hours)
            min_runs = stage_config.get("min_test_runs", record.test_runs_required)

            # Check minimum time elapsed
            entered_at = record.entered_stage_at
            if entered_at.tzinfo is None:
                entered_at = entered_at.replace(tzinfo=timezone.utc)
            hours_elapsed = (now - entered_at).total_seconds() / 3600

            if hours_elapsed < min_hours or record.test_runs_completed < min_runs:
                unchanged.append({
                    "layer": record.layer_name,
                    "stage": record.stage,
                    "hours_remaining": max(0, min_hours - hours_elapsed),
                    "runs_remaining": max(0, min_runs - record.test_runs_completed),
                })
                continue

            # Compute effectiveness (simple: detection - FP penalty)
            effectiveness = record.detection_rate_avg - (record.false_positive_rate_avg * 0.5)

            # Check rejection
            if effectiveness < record.rejection_threshold:
                record.rejected = True
                record.rejection_reason = (
                    f"Effectiveness {effectiveness:.3f} below rejection threshold "
                    f"{record.rejection_threshold} at stage '{record.stage}'"
                )
                self.session.commit()
                rejected.append({
                    "layer": record.layer_name,
                    "stage": record.stage,
                    "effectiveness": effectiveness,
                    "reason": record.rejection_reason,
                })
                logger.warning(
                    "Layer rejected from staging",
                    extra={"extra_data": {
                        "layer": record.layer_name,
                        "stage": record.stage,
                        "effectiveness": effectiveness,
                    }},
                )
                continue

            # Check promotion
            if effectiveness >= record.promotion_threshold:
                next_stage = self._next_stage(record.stage)
                if next_stage == "production":
                    record.promoted = True
                    record.stage = "production"
                    self.session.commit()
                    promoted.append({
                        "layer": record.layer_name,
                        "from_stage": record.stage,
                        "to_stage": "production",
                        "effectiveness": effectiveness,
                    })
                    logger.info(
                        "Layer promoted to production",
                        extra={"extra_data": {
                            "layer": record.layer_name,
                            "effectiveness": effectiveness,
                        }},
                    )
                else:
                    # Advance to next stage
                    old_stage = record.stage
                    next_config = _STAGE_CONFIG[next_stage]
                    record.stage = next_stage
                    record.entered_stage_at = now
                    record.test_runs_completed = 0
                    record.detection_rate_avg = 0.0
                    record.false_positive_rate_avg = 0.0
                    record.min_evaluation_hours = next_config["min_hours"]
                    record.test_runs_required = next_config["min_test_runs"]
                    record.promotion_threshold = next_config["promotion_threshold"]
                    record.rejection_threshold = next_config["rejection_threshold"]
                    self.session.commit()
                    promoted.append({
                        "layer": record.layer_name,
                        "from_stage": old_stage,
                        "to_stage": next_stage,
                        "effectiveness": effectiveness,
                    })
                    logger.info(
                        "Layer promoted to next stage",
                        extra={"extra_data": {
                            "layer": record.layer_name,
                            "from": old_stage,
                            "to": next_stage,
                        }},
                    )
            else:
                unchanged.append({
                    "layer": record.layer_name,
                    "stage": record.stage,
                    "effectiveness": effectiveness,
                    "note": "Meets minimum but below promotion threshold",
                })

        return {
            "promoted": promoted,
            "rejected": rejected,
            "unchanged": unchanged,
        }

    def _next_stage(self, current: str) -> str:
        """Return the next stage in the pipeline."""
        try:
            idx = _STAGES.index(current)
            return _STAGES[min(idx + 1, len(_STAGES) - 1)]
        except ValueError:
            return "shadow"

    def get_staging_status(self) -> list[dict]:
        """Return current staging status for all layers."""
        records = (
            self.session.query(StagingRecord)
            .filter_by(promoted=False, rejected=False)
            .all()
        )
        return [
            {
                "layer": r.layer_name,
                "stage": r.stage,
                "test_runs": r.test_runs_completed,
                "runs_required": r.test_runs_required,
                "detection_rate_avg": r.detection_rate_avg,
                "fp_rate_avg": r.false_positive_rate_avg,
            }
            for r in records
        ]

    def is_production_ready(self, layer_name: str) -> bool:
        """Check if a layer has been promoted to production."""
        record = (
            self.session.query(StagingRecord)
            .filter_by(layer_name=layer_name, promoted=True)
            .first()
        )
        return record is not None
