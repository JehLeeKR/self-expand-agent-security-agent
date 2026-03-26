"""Self-learning and self-adaptation system for defense layers.

Analyzes test results over time to identify patterns in what works and what
doesn't, then uses Claude Code CLI to autonomously adapt defense layers:

- Tune detection thresholds based on false positive / false negative data
- Add new patterns discovered from attack payloads that bypassed defenses
- Remove patterns that consistently cause false positives
- Adjust scoring weights based on real-world effectiveness data

Architecture (Part 3 — Claude Code CLI Management/CI-CD):
This module operates in the management layer. It reads test history from the DB,
identifies adaptation opportunities, then invokes Claude Code CLI to make the
actual code modifications — keeping the human-out-of-the-loop cycle intact.
"""

from __future__ import annotations

import json
import uuid
from collections import defaultdict
from datetime import datetime, timezone

from src.db.models import AdaptationLog, TestRun
from src.db.result_store import ResultStore
from src.utils.claude_code import ClaudeCode
from src.utils.logging import get_logger

logger = get_logger()

_ADAPTATION_PROMPT = """\
You are performing a SELF-ADAPTATION of a defense layer based on test results.

## Task
Read the defense layer file at `{file_path}` and modify it to address the
following issues identified from automated testing.

## Performance Data
- Current detection rate: {detection_rate:.1%}
- Current false positive rate: {fp_rate:.1%}
- Current prevention rate: {prevention_rate:.1%}
- Test runs analyzed: {run_count}

## Identified Issues
{issues_json}

## Adaptation Instructions
{adaptation_instructions}

## Rules
- Do NOT change the class name, layer name, or priority
- Do NOT remove existing imports or break the BaseDefenseLayer interface
- Keep the same file path: {file_path}
- All changes must maintain or improve detection rate
- Verify with: python3 -m py_compile {file_path}
- Add a comment at the top noting this adaptation: `# Adapted: {{date}} - {{reason}}`
"""


class SelfLearner:
    """Learns from test results and adapts defense layers autonomously.

    Operates on a feedback loop:
    1. Analyze recent test results for each layer
    2. Identify adaptation opportunities (threshold mistuning, pattern gaps)
    3. Use Claude Code CLI to implement adaptations
    4. Record changes for audit trail
    """

    def __init__(
        self,
        claude_code: ClaudeCode,
        result_store: ResultStore,
        config: dict | None = None,
    ) -> None:
        self.claude_code = claude_code
        self.result_store = result_store
        self.session = result_store.session
        self.config = config or {}

        robustness = self.config.get("robustness", {})
        self.min_runs_for_adaptation = robustness.get("min_runs_for_adaptation", 10)
        self.fp_rate_ceiling = robustness.get("fp_rate_ceiling", 0.10)
        self.detection_floor = robustness.get("detection_floor", 0.60)
        self.improvement_threshold = robustness.get("improvement_threshold", 0.05)

    def _analyze_layer_performance(self, layer_name: str) -> dict | None:
        """Analyze recent test performance for a specific layer.

        Returns performance summary dict or None if insufficient data.
        """
        runs = self.result_store.get_latest_runs(limit=200)

        # Filter runs where this layer was active
        layer_runs = []
        for run in runs:
            try:
                active = json.loads(run.defense_layers_active) if run.defense_layers_active else []
            except (json.JSONDecodeError, TypeError):
                active = []
            if layer_name in active:
                layer_runs.append(run)

        if len(layer_runs) < self.min_runs_for_adaptation:
            return None

        detection_rates = [r.detection_rate or 0.0 for r in layer_runs]
        prevention_rates = [r.prevention_rate or 0.0 for r in layer_runs]
        fp_rates = [r.false_positive_rate or 0.0 for r in layer_runs]
        exfil_rates = [r.exfiltration_rate or 0.0 for r in layer_runs]

        avg = lambda lst: sum(lst) / len(lst) if lst else 0.0

        # Trend analysis: split into first half / second half
        mid = len(layer_runs) // 2
        first_half_detection = avg(detection_rates[:mid]) if mid > 0 else 0.0
        second_half_detection = avg(detection_rates[mid:])
        detection_trend = second_half_detection - first_half_detection

        return {
            "layer_name": layer_name,
            "run_count": len(layer_runs),
            "detection_rate": avg(detection_rates),
            "prevention_rate": avg(prevention_rates),
            "false_positive_rate": avg(fp_rates),
            "exfiltration_rate": avg(exfil_rates),
            "detection_trend": detection_trend,
            "detection_rates_series": detection_rates[-20:],  # last 20
            "fp_rates_series": fp_rates[-20:],
        }

    def _identify_adaptations(self, perf: dict) -> list[dict]:
        """Identify what adaptations are needed based on performance data."""
        issues = []

        # High false positive rate
        if perf["false_positive_rate"] > self.fp_rate_ceiling:
            issues.append({
                "type": "high_false_positives",
                "severity": "high",
                "detail": (
                    f"FP rate {perf['false_positive_rate']:.1%} exceeds ceiling "
                    f"{self.fp_rate_ceiling:.1%}"
                ),
                "instruction": (
                    "Raise the block threshold (currently >= 0.85) slightly to reduce "
                    "false positives. Also review regex patterns for overly broad matches "
                    "and tighten them. Consider adding whitelist patterns for common "
                    "legitimate inputs that trigger false positives."
                ),
            })

        # Low detection rate
        if perf["detection_rate"] < self.detection_floor:
            issues.append({
                "type": "low_detection",
                "severity": "high",
                "detail": (
                    f"Detection rate {perf['detection_rate']:.1%} below floor "
                    f"{self.detection_floor:.1%}"
                ),
                "instruction": (
                    "Add more detection patterns. Lower the flag threshold (currently "
                    ">= 0.45) to catch more borderline cases. Add pattern families for "
                    "attack variants that may be slipping through. Consider adding "
                    "character-level analysis for obfuscated payloads."
                ),
            })

        # Declining detection trend
        if perf["detection_trend"] < -0.1:
            issues.append({
                "type": "declining_effectiveness",
                "severity": "medium",
                "detail": (
                    f"Detection trend is declining: {perf['detection_trend']:+.1%} "
                    f"between first and second half of test period"
                ),
                "instruction": (
                    "The defense is becoming less effective over time, possibly due to "
                    "evolving attack patterns. Add detection rules for newer attack "
                    "variations. Consider adding adaptive pattern matching that looks "
                    "for semantic intent rather than just syntax."
                ),
            })

        # High exfiltration despite detection
        if perf["exfiltration_rate"] > 0.2 and perf["detection_rate"] > 0.5:
            issues.append({
                "type": "detection_without_prevention",
                "severity": "high",
                "detail": (
                    f"Detecting {perf['detection_rate']:.1%} but still allowing "
                    f"{perf['exfiltration_rate']:.1%} exfiltration"
                ),
                "instruction": (
                    "The layer is detecting threats but not blocking them effectively. "
                    "Review the confidence scoring — detected threats should have higher "
                    "confidence scores. Consider lowering the block threshold for "
                    "high-severity patterns, or adding a secondary check that converts "
                    "flags to blocks when multiple signals co-occur."
                ),
            })

        return issues

    def adapt_layer(self, layer_name: str, file_path: str) -> dict | None:
        """Analyze and adapt a single defense layer.

        Returns adaptation result dict or None if no adaptation needed.
        """
        perf = self._analyze_layer_performance(layer_name)
        if not perf:
            logger.info(
                "Insufficient data for adaptation",
                extra={"extra_data": {"layer": layer_name}},
            )
            return None

        issues = self._identify_adaptations(perf)
        if not issues:
            logger.info(
                "No adaptations needed",
                extra={"extra_data": {
                    "layer": layer_name,
                    "detection": perf["detection_rate"],
                    "fp_rate": perf["false_positive_rate"],
                }},
            )
            return None

        logger.info(
            "Adapting defense layer",
            extra={"extra_data": {
                "layer": layer_name,
                "issues": len(issues),
                "types": [i["type"] for i in issues],
            }},
        )

        # Build combined adaptation instructions
        instructions = "\n\n".join(
            f"### Issue {i+1}: {issue['type']} (severity: {issue['severity']})\n"
            f"{issue['detail']}\n\n"
            f"**Fix**: {issue['instruction']}"
            for i, issue in enumerate(issues)
        )

        prompt = _ADAPTATION_PROMPT.format(
            file_path=file_path,
            detection_rate=perf["detection_rate"],
            fp_rate=perf["false_positive_rate"],
            prevention_rate=perf["prevention_rate"],
            run_count=perf["run_count"],
            issues_json=json.dumps(issues, indent=2),
            adaptation_instructions=instructions,
        )

        # Capture old state for audit log
        old_value = {
            "detection_rate": perf["detection_rate"],
            "false_positive_rate": perf["false_positive_rate"],
            "prevention_rate": perf["prevention_rate"],
        }

        result = self.claude_code.implement(prompt, file_path)
        if not result.get("success"):
            logger.error(
                "Adaptation implementation failed",
                extra={"extra_data": {"layer": layer_name}},
            )
            return None

        verify = self.claude_code.verify_code(file_path)
        if not verify.get("success"):
            logger.error("Adapted code failed verification", extra={"extra_data": {"layer": layer_name}})
            return None

        # Record adaptation
        for issue in issues:
            log = AdaptationLog(
                id=str(uuid.uuid4()),
                layer_name=layer_name,
                adaptation_type=issue["type"],
                old_value=json.dumps(old_value),
                new_value=json.dumps({"adapted": True, "issue": issue["type"]}),
                reason=issue["detail"],
            )
            self.session.add(log)

        self.session.commit()

        logger.info(
            "Layer adapted successfully",
            extra={"extra_data": {
                "layer": layer_name,
                "adaptations": len(issues),
            }},
        )

        return {
            "layer": layer_name,
            "adaptations": issues,
            "old_performance": old_value,
        }

    def run(self) -> list[dict]:
        """Run self-learning adaptation across all active layers.

        Returns list of adaptation results.
        """
        active_layers = self.result_store.get_active_layers()
        results = []

        for layer_db in active_layers:
            file_path = layer_db.module_path
            # Convert module path to file path if needed
            if "." in file_path and not file_path.endswith(".py"):
                parts = file_path.rsplit(".", 1)
                file_path = parts[0].replace(".", "/") + ".py"

            result = self.adapt_layer(layer_db.name, file_path)
            if result:
                results.append(result)

        logger.info(
            "Self-learning cycle complete",
            extra={"extra_data": {
                "layers_analyzed": len(active_layers),
                "layers_adapted": len(results),
            }},
        )
        return results
