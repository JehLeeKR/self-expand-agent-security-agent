"""Defense evaluation engine that computes effectiveness metrics from test runs."""

import json
import uuid
from datetime import datetime, timezone

from src.db.models import TestRun
from src.db.result_store import ResultStore
from src.utils.logging import get_logger

logger = get_logger()


class DefenseEvaluator:
    """Evaluates defense effectiveness by comparing defended vs undefended test runs."""

    def __init__(self, result_store: ResultStore) -> None:
        self.result_store = result_store

    def evaluate_run(self, undefended: dict, defended: dict) -> dict:
        """Compare results with vs without defenses and compute metrics.

        Args:
            undefended: Attack results dict without defenses active.
            defended: Attack results dict with defenses active.

        Returns:
            A dict of effectiveness metrics:
            - detection_rate: fraction of attacks detected or blocked by defenses
            - prevention_rate: fraction of attacks fully blocked by defenses
            - exfiltration_rate: fraction of attacks that leaked data with defenses on
            - false_positive_rate: fraction of clean payloads that were blocked
            - latency_overhead_ms: average added latency from the defense pipeline
        """
        defended_total = defended.get("attacks_total", 0)
        undefended_total = undefended.get("attacks_total", 0)

        if defended_total == 0:
            return {
                "detection_rate": 0.0,
                "prevention_rate": 0.0,
                "exfiltration_rate": 0.0,
                "false_positive_rate": 0.0,
                "latency_overhead_ms": 0.0,
            }

        # Detection rate: attacks that were either blocked or detected
        detected_or_blocked = defended.get("blocked", 0) + defended.get("detected", 0)
        detection_rate = detected_or_blocked / defended_total

        # Prevention rate: attacks fully blocked
        prevention_rate = defended.get("blocked", 0) / defended_total

        # Exfiltration rate: data leaks that still occurred with defenses
        exfiltration_rate = defended.get("leaked", 0) / defended_total

        # False positive rate: clean payloads (those clean in undefended run)
        # that were incorrectly blocked in the defended run
        undefended_clean = undefended.get("clean", 0)
        if undefended_clean > 0:
            # Count payloads that were clean without defenses but blocked with defenses
            defended_details = defended.get("details", [])
            undefended_details = undefended.get("details", [])
            false_positives = 0
            for u_detail, d_detail in zip(undefended_details, defended_details):
                if u_detail.get("outcome") == "clean" and d_detail.get("outcome") == "blocked":
                    false_positives += 1
            false_positive_rate = false_positives / undefended_clean
        else:
            false_positive_rate = 0.0

        # Latency overhead: average defense pipeline latency from defended details
        defended_details = defended.get("details", [])
        latencies = [
            d.get("defense_latency_ms", 0.0)
            for d in defended_details
            if "defense_latency_ms" in d
        ]
        latency_overhead_ms = sum(latencies) / len(latencies) if latencies else 0.0

        metrics = {
            "detection_rate": round(detection_rate, 4),
            "prevention_rate": round(prevention_rate, 4),
            "exfiltration_rate": round(exfiltration_rate, 4),
            "false_positive_rate": round(false_positive_rate, 4),
            "latency_overhead_ms": round(latency_overhead_ms, 2),
        }

        logger.info(
            "Run evaluation complete",
            extra={"extra_data": metrics},
        )
        return metrics

    def evaluate_layer(self, layer_name: str) -> dict:
        """Aggregate effectiveness metrics for a specific defense layer across all runs.

        Args:
            layer_name: The name of the defense layer to evaluate.

        Returns:
            A dict with aggregated effectiveness metrics, or empty metrics if no data.
        """
        all_runs = self.result_store.get_latest_runs(limit=500)
        matching_runs = [
            run for run in all_runs
            if layer_name in (json.loads(run.defense_layers_active) if run.defense_layers_active else [])
        ]

        if not matching_runs:
            logger.info(
                "No test runs found for layer",
                extra={"extra_data": {"layer_name": layer_name}},
            )
            return {
                "layer_name": layer_name,
                "total_runs": 0,
                "avg_detection_rate": 0.0,
                "avg_prevention_rate": 0.0,
                "avg_exfiltration_rate": 0.0,
                "avg_false_positive_rate": 0.0,
                "avg_latency_overhead_ms": 0.0,
            }

        total = len(matching_runs)
        avg_detection = sum(r.detection_rate or 0.0 for r in matching_runs) / total
        avg_prevention = sum(r.prevention_rate or 0.0 for r in matching_runs) / total
        avg_exfiltration = sum(r.exfiltration_rate or 0.0 for r in matching_runs) / total
        avg_fp = sum(r.false_positive_rate or 0.0 for r in matching_runs) / total
        avg_latency = sum(r.latency_overhead_ms or 0.0 for r in matching_runs) / total

        metrics = {
            "layer_name": layer_name,
            "total_runs": total,
            "avg_detection_rate": round(avg_detection, 4),
            "avg_prevention_rate": round(avg_prevention, 4),
            "avg_exfiltration_rate": round(avg_exfiltration, 4),
            "avg_false_positive_rate": round(avg_fp, 4),
            "avg_latency_overhead_ms": round(avg_latency, 2),
        }

        logger.info(
            "Layer evaluation complete",
            extra={"extra_data": metrics},
        )
        return metrics

    def run(self, attack_results: dict, threat_id: str, victim_profile: str) -> TestRun:
        """Evaluate attack results and store as a TestRun in the database.

        Args:
            attack_results: The results dict from AttackRunner (defended run).
            threat_id: The classified threat ID these results correspond to.
            victim_profile: The victim profile used in the test.

        Returns:
            The persisted TestRun record.
        """
        total = attack_results.get("attacks_total", 0)
        blocked = attack_results.get("blocked", 0)
        detected = attack_results.get("detected", 0)
        leaked = attack_results.get("leaked", 0)

        if total > 0:
            detection_rate = (blocked + detected) / total
            prevention_rate = blocked / total
            exfiltration_rate = leaked / total
        else:
            detection_rate = 0.0
            prevention_rate = 0.0
            exfiltration_rate = 0.0

        # Extract latency info from details
        details = attack_results.get("details", [])
        latencies = [
            d.get("defense_latency_ms", 0.0)
            for d in details
            if "defense_latency_ms" in d
        ]
        latency_overhead_ms = sum(latencies) / len(latencies) if latencies else 0.0

        # Get currently active defense layers
        active_layers = self.result_store.get_active_layers()
        layer_names = [layer.name for layer in active_layers]

        test_run = self.result_store.add_test_run(
            threat_id=threat_id,
            victim_profile=victim_profile,
            defense_layers_active=layer_names,
            detection_rate=round(detection_rate, 4),
            prevention_rate=round(prevention_rate, 4),
            exfiltration_rate=round(exfiltration_rate, 4),
            false_positive_rate=0.0,  # Requires undefended baseline for accurate calc
            latency_overhead_ms=round(latency_overhead_ms, 2),
            details=attack_results,
        )

        logger.info(
            "Test run recorded",
            extra={"extra_data": {
                "run_id": test_run.id,
                "threat_id": threat_id,
                "victim_profile": victim_profile,
                "detection_rate": test_run.detection_rate,
                "prevention_rate": test_run.prevention_rate,
            }},
        )
        return test_run
