"""Defense layer optimization based on test result analysis."""

from __future__ import annotations

import json
from collections import defaultdict

from src.db.models import DefenseLayer, TestRun
from src.db.result_store import ResultStore
from src.defender.layer_registry import LayerRegistry
from src.utils.logging import get_logger

logger = get_logger()

# Layers with effectiveness below this threshold are candidates for deactivation.
_DEACTIVATION_THRESHOLD = 0.15

# Minimum number of test runs before a layer can be evaluated for deactivation.
_MIN_RUNS_FOR_EVALUATION = 5


class DefenseOptimizer:
    """Analyzes defense layer performance and optimizes the pipeline.

    Optimization actions include:
    - Reordering layers based on detection rates and latency.
    - Deactivating consistently low-performing layers.
    - Identifying threat categories with insufficient coverage.
    """

    def __init__(
        self,
        layer_registry: LayerRegistry,
        result_store: ResultStore,
    ) -> None:
        self.layer_registry = layer_registry
        self.result_store = result_store

    # ------------------------------------------------------------------
    # Effectiveness analysis
    # ------------------------------------------------------------------

    def analyze_effectiveness(self) -> dict:
        """Review test results per layer and compute effectiveness scores.

        Returns a dict keyed by layer name with metrics:
        - detection_rate_avg: Average detection rate across test runs.
        - prevention_rate_avg: Average prevention rate.
        - false_positive_rate_avg: Average false positive rate.
        - latency_overhead_avg_ms: Average latency overhead in ms.
        - run_count: Number of test runs involving this layer.
        - effectiveness_score: Composite score (0..1).
        """
        active_layers = self.result_store.get_active_layers()
        test_runs = self.result_store.get_latest_runs(limit=500)

        # Index test runs by which layers were active.
        layer_runs: dict[str, list[TestRun]] = defaultdict(list)
        for run in test_runs:
            try:
                active_names = json.loads(run.defense_layers_active) if run.defense_layers_active else []
            except (json.JSONDecodeError, TypeError):
                active_names = []
            for layer_name in active_names:
                layer_runs[layer_name].append(run)

        analysis: dict[str, dict] = {}

        for layer in active_layers:
            runs = layer_runs.get(layer.name, [])
            run_count = len(runs)

            if run_count == 0:
                analysis[layer.name] = {
                    "detection_rate_avg": 0.0,
                    "prevention_rate_avg": 0.0,
                    "false_positive_rate_avg": 0.0,
                    "latency_overhead_avg_ms": 0.0,
                    "run_count": 0,
                    "effectiveness_score": 0.0,
                }
                continue

            detection_avg = sum(r.detection_rate or 0.0 for r in runs) / run_count
            prevention_avg = sum(r.prevention_rate or 0.0 for r in runs) / run_count
            fp_avg = sum(r.false_positive_rate or 0.0 for r in runs) / run_count
            latency_avg = sum(r.latency_overhead_ms or 0.0 for r in runs) / run_count

            # Composite effectiveness: reward detection/prevention, penalize FP and latency.
            effectiveness = (
                detection_avg * 0.4
                + prevention_avg * 0.4
                - fp_avg * 0.15
                - min(latency_avg / 1000.0, 0.1) * 0.05  # Cap latency penalty
            )
            effectiveness = max(0.0, min(1.0, effectiveness))

            analysis[layer.name] = {
                "detection_rate_avg": round(detection_avg, 4),
                "prevention_rate_avg": round(prevention_avg, 4),
                "false_positive_rate_avg": round(fp_avg, 4),
                "latency_overhead_avg_ms": round(latency_avg, 2),
                "run_count": run_count,
                "effectiveness_score": round(effectiveness, 4),
            }

            # Persist the computed effectiveness score.
            self.result_store.update_layer_effectiveness(layer.name, effectiveness)

        return analysis

    # ------------------------------------------------------------------
    # Optimization
    # ------------------------------------------------------------------

    def optimize(self) -> dict:
        """Run optimization: reorder layers, deactivate underperformers, identify gaps.

        Returns an optimization report dict.
        """
        analysis = self.analyze_effectiveness()

        deactivated: list[str] = []
        reordered: list[dict] = []
        gaps: list[str] = []

        # 1. Deactivate low performers with sufficient evaluation data.
        for layer_name, metrics in analysis.items():
            if (
                metrics["run_count"] >= _MIN_RUNS_FOR_EVALUATION
                and metrics["effectiveness_score"] < _DEACTIVATION_THRESHOLD
            ):
                self.result_store.deactivate_layer(layer_name)
                deactivated.append(layer_name)
                logger.info(
                    "Deactivated underperforming layer",
                    extra={
                        "extra_data": {
                            "layer": layer_name,
                            "effectiveness": metrics["effectiveness_score"],
                            "run_count": metrics["run_count"],
                        }
                    },
                )

        # 2. Suggest reordering based on effectiveness.
        # Higher-effectiveness layers should run earlier (lower priority number)
        # among layers with the same functional group.
        scored_layers: list[tuple[str, float, int]] = []
        for layer in self.layer_registry.get_pipeline():
            score = analysis.get(layer.name, {}).get("effectiveness_score", 0.0)
            scored_layers.append((layer.name, score, layer.priority))

        # Sort by effectiveness descending -- propose new priority assignments.
        scored_layers.sort(key=lambda x: -x[1])
        for new_order, (name, score, current_priority) in enumerate(scored_layers):
            suggested_priority = (new_order + 1) * 10
            if suggested_priority != current_priority:
                reordered.append({
                    "layer": name,
                    "current_priority": current_priority,
                    "suggested_priority": suggested_priority,
                    "effectiveness_score": score,
                })

        # 3. Gap analysis -- find uncovered threat categories.
        coverage = self.layer_registry.coverage_report()
        gaps = coverage.get("uncovered", [])

        # Also flag categories where all covering layers perform poorly.
        for category, covering_layers in coverage.get("categories", {}).items():
            active_covering = [
                ln for ln in covering_layers
                if ln not in deactivated
            ]
            if not active_covering:
                if category not in gaps:
                    gaps.append(category)

        report = {
            "analysis": analysis,
            "deactivated_layers": deactivated,
            "reorder_suggestions": reordered,
            "coverage_gaps": sorted(gaps),
            "total_layers_evaluated": len(analysis),
        }

        logger.info(
            "Optimization complete",
            extra={
                "extra_data": {
                    "deactivated": len(deactivated),
                    "reorder_suggestions": len(reordered),
                    "coverage_gaps": len(gaps),
                }
            },
        )

        return report

    # ------------------------------------------------------------------
    # Full cycle
    # ------------------------------------------------------------------

    def run(self) -> dict:
        """Run full analysis and optimization cycle.

        Returns the optimization report.
        """
        logger.info("Starting defense optimization cycle")
        report = self.optimize()
        logger.info(
            "Defense optimization cycle complete",
            extra={"extra_data": {"report_summary": {
                "deactivated": len(report["deactivated_layers"]),
                "gaps": len(report["coverage_gaps"]),
            }}},
        )
        return report
