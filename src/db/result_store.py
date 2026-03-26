"""CRUD operations for test results and defense layer metadata."""

import json
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from src.db.models import DefenseLayer, TestRun


class ResultStore:
    def __init__(self, session: Session):
        self.session = session

    # --- Defense Layers ---

    def register_layer(
        self, name: str, module_path: str, priority: int,
        threat_categories: list[str], detection_rules: list[dict] | None = None,
    ) -> DefenseLayer:
        existing = self.session.query(DefenseLayer).filter_by(name=name).first()
        if existing:
            existing.detection_rules = json.dumps(detection_rules or [])
            existing.threat_categories = json.dumps(threat_categories)
            existing.updated_at = datetime.now(timezone.utc)
            self.session.commit()
            return existing

        layer = DefenseLayer(
            name=name,
            module_path=module_path,
            priority=priority,
            threat_categories=json.dumps(threat_categories),
            detection_rules=json.dumps(detection_rules or []),
        )
        self.session.add(layer)
        self.session.commit()
        return layer

    def get_active_layers(self) -> list[DefenseLayer]:
        return (
            self.session.query(DefenseLayer)
            .filter_by(is_active=True)
            .order_by(DefenseLayer.priority)
            .all()
        )

    def update_layer_effectiveness(self, name: str, score: float) -> None:
        layer = self.session.query(DefenseLayer).filter_by(name=name).first()
        if layer:
            layer.effectiveness_score = score
            layer.updated_at = datetime.now(timezone.utc)
            self.session.commit()

    def deactivate_layer(self, name: str) -> None:
        layer = self.session.query(DefenseLayer).filter_by(name=name).first()
        if layer:
            layer.is_active = False
            self.session.commit()

    # --- Test Runs ---

    def add_test_run(
        self, threat_id: str, victim_profile: str,
        defense_layers_active: list[str], detection_rate: float,
        prevention_rate: float, exfiltration_rate: float,
        false_positive_rate: float, latency_overhead_ms: float,
        details: dict | None = None,
    ) -> TestRun:
        run = TestRun(
            id=str(uuid.uuid4()),
            threat_id=threat_id,
            victim_profile=victim_profile,
            defense_layers_active=json.dumps(defense_layers_active),
            detection_rate=detection_rate,
            prevention_rate=prevention_rate,
            exfiltration_rate=exfiltration_rate,
            false_positive_rate=false_positive_rate,
            latency_overhead_ms=latency_overhead_ms,
            details=json.dumps(details or {}),
        )
        self.session.add(run)
        self.session.commit()
        return run

    def get_runs_for_threat(self, threat_id: str) -> list[TestRun]:
        return (
            self.session.query(TestRun)
            .filter_by(threat_id=threat_id)
            .order_by(TestRun.run_at.desc())
            .all()
        )

    def get_latest_runs(self, limit: int = 50) -> list[TestRun]:
        return (
            self.session.query(TestRun)
            .order_by(TestRun.run_at.desc())
            .limit(limit)
            .all()
        )
