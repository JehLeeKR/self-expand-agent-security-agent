"""Periodic review system — Claude Code CLI audits defense layers on a schedule.

Regular code reviews ensure defense quality doesn't degrade over time.
Claude Code CLI performs four types of reviews:

1. **Security audit**: Check for vulnerabilities in defense layer code
2. **Code quality**: Check for code smells, complexity, maintainability
3. **Effectiveness review**: Analyze if detection logic still covers current threats
4. **Regression check**: Verify that recent changes haven't degraded coverage

Architecture (Part 3 — Claude Code CLI Management/CI-CD):
The reviewer operates as the "quality gate" in the CI/CD cycle. It runs after
every implementation or adaptation cycle, and periodically on all active layers.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from src.db.models import ReviewRecord
from src.db.result_store import ResultStore
from src.utils.claude_code import ClaudeCode
from src.utils.logging import get_logger

logger = get_logger()

_REVIEW_PROMPTS = {
    "security_audit": """\
Perform a thorough SECURITY AUDIT of the defense layer at `{file_path}`.

Check for:
1. ReDoS patterns (catastrophic backtracking in regex)
2. Information leakage (detection details exposed in responses)
3. Injection vulnerabilities (attacker-controlled input in string operations)
4. Resource exhaustion (unbounded loops, memory allocation)
5. Unsafe operations (file I/O, network, exec/eval)
6. Timing side channels (detection time varies with input)
7. Bypass techniques (known evasion methods for this detection approach)

Return JSON:
{{"findings": [{{"severity": "...", "type": "...", "line": ..., "description": "...", "fix": "..."}}], "overall_severity": "...", "recommendation": "..."}}
""",

    "code_quality": """\
Perform a CODE QUALITY REVIEW of the defense layer at `{file_path}`.

Check for:
1. Cyclomatic complexity — is the inspect() method too complex?
2. Code duplication — are there repeated patterns that should be extracted?
3. Type safety — are all inputs properly typed and validated?
4. Error handling — are exceptions caught appropriately?
5. Performance — are regex patterns pre-compiled? Are there unnecessary allocations?
6. Testability — can the detection logic be unit-tested independently?
7. Documentation — are detection rules and thresholds documented?

Return JSON:
{{"findings": [{{"severity": "...", "type": "...", "line": ..., "description": "...", "fix": "..."}}], "quality_score": <0.0-1.0>, "recommendation": "..."}}
""",

    "effectiveness_review": """\
Perform an EFFECTIVENESS REVIEW of the defense layer at `{file_path}`.

Context: This layer has detection rate {detection_rate:.1%} and false positive rate {fp_rate:.1%}.

Check:
1. Are the detection patterns comprehensive enough for the threat category?
2. Are there known attack variants that would bypass these patterns?
3. Are the confidence thresholds calibrated correctly?
4. Is the scoring formula balanced between detection and false positives?
5. Are there emerging attack techniques this layer doesn't cover?
6. Could the detection be improved without major restructuring?

Return JSON:
{{"findings": [{{"type": "...", "description": "...", "suggested_fix": "..."}}], "coverage_assessment": "...", "recommendation": "..."}}
""",

    "regression_check": """\
Perform a REGRESSION CHECK on the defense layer at `{file_path}`.

This layer was recently modified (adapted or transformed). Verify:
1. All original detection capabilities are still present
2. The base class interface is correctly implemented
3. No detection rules were accidentally removed
4. Scoring thresholds are still within acceptable ranges
5. The layer compiles and follows established patterns

Also read src/defender/layers/base.py to verify interface compliance.

Return JSON:
{{"findings": [{{"type": "...", "description": "..."}}], "regression_detected": <boolean>, "recommendation": "..."}}
""",
}


class PeriodicReviewer:
    """Runs scheduled Claude Code CLI reviews of defense layers.

    Each review type serves a different purpose in the CI/CD lifecycle:
    - security_audit: Deep security check (every 72h)
    - code_quality: Code quality maintenance (every 48h)
    - effectiveness_review: Detection coverage analysis (after every test cycle)
    - regression_check: Post-modification verification (after every adaptation)
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

    def review_layer(
        self,
        layer_name: str,
        file_path: str,
        review_type: str,
        detection_rate: float = 0.0,
        fp_rate: float = 0.0,
    ) -> dict | None:
        """Run a specific type of review on a defense layer.

        Returns review findings dict, or None on failure.
        """
        if review_type not in _REVIEW_PROMPTS:
            logger.error(f"Unknown review type: {review_type}")
            return None

        prompt = _REVIEW_PROMPTS[review_type].format(
            file_path=file_path,
            layer_name=layer_name,
            detection_rate=detection_rate,
            fp_rate=fp_rate,
        )

        result = self.claude_code.implement(prompt, None)
        if not result.get("success"):
            logger.error(
                "Review failed",
                extra={"extra_data": {"layer": layer_name, "type": review_type}},
            )
            return None

        # Parse review response
        output = result.get("output", "")
        text = output.get("result", str(output)) if isinstance(output, dict) else str(output)

        try:
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                findings = json.loads(text[start:end])
            else:
                findings = {"findings": [], "recommendation": "Unable to parse review output"}
        except json.JSONDecodeError:
            findings = {"findings": [], "recommendation": "Unable to parse review output"}

        # Determine severity
        issue_list = findings.get("findings", [])
        if any(f.get("severity") == "critical" for f in issue_list):
            severity = "critical"
        elif any(f.get("severity") == "high" for f in issue_list):
            severity = "high"
        elif any(f.get("severity") == "medium" for f in issue_list):
            severity = "medium"
        elif issue_list:
            severity = "low"
        else:
            severity = "info"

        # Record review
        record = ReviewRecord(
            id=str(uuid.uuid4()),
            layer_name=layer_name,
            review_type=review_type,
            findings=json.dumps(findings),
            severity=severity,
        )
        self.session.add(record)
        self.session.commit()

        logger.info(
            "Review complete",
            extra={"extra_data": {
                "layer": layer_name,
                "type": review_type,
                "severity": severity,
                "findings_count": len(issue_list),
            }},
        )

        return findings

    def auto_fix(self, layer_name: str, file_path: str, findings: dict) -> bool:
        """Attempt to auto-fix issues found during review.

        Uses Claude Code CLI to apply fixes for non-critical issues.
        Returns True if fixes were applied successfully.
        """
        issues = findings.get("findings", [])
        fixable = [f for f in issues if f.get("fix") or f.get("suggested_fix")]

        if not fixable:
            return False

        fixes_description = "\n".join(
            f"- {f.get('type', 'issue')}: {f.get('fix') or f.get('suggested_fix')}"
            for f in fixable
        )

        prompt = (
            f"Apply the following fixes to the defense layer at `{file_path}`:\n\n"
            f"{fixes_description}\n\n"
            f"Read the file first, apply each fix carefully, and verify:\n"
            f"python3 -m py_compile {file_path}\n\n"
            f"Do NOT change the class name, layer name, or priority.\n"
            f"Do NOT remove existing detection capabilities.\n"
        )

        result = self.claude_code.implement(prompt, file_path)
        if not result.get("success"):
            return False

        verify = self.claude_code.verify_code(file_path)
        if not verify.get("success"):
            return False

        # Record the fix
        record = ReviewRecord(
            id=str(uuid.uuid4()),
            layer_name=layer_name,
            review_type="auto_fix",
            findings=json.dumps({"fixed_issues": fixable}),
            severity="info",
            action_taken=json.dumps({"fixes_applied": len(fixable)}),
        )
        self.session.add(record)
        self.session.commit()

        logger.info(
            "Auto-fix applied",
            extra={"extra_data": {
                "layer": layer_name,
                "fixes": len(fixable),
            }},
        )
        return True

    def run(self, review_types: list[str] | None = None) -> dict:
        """Run periodic reviews across all active layers.

        Args:
            review_types: Specific review types to run, or None for all.

        Returns combined review report.
        """
        types = review_types or ["security_audit", "code_quality"]
        active_layers = self.result_store.get_active_layers()
        report = {"reviews": [], "auto_fixes": []}

        for layer_db in active_layers:
            file_path = layer_db.module_path
            if "." in file_path and not file_path.endswith(".py"):
                parts = file_path.rsplit(".", 1)
                file_path = parts[0].replace(".", "/") + ".py"

            if not Path(file_path).exists():
                continue

            for review_type in types:
                # Check if recently reviewed
                latest = (
                    self.session.query(ReviewRecord)
                    .filter_by(layer_name=layer_db.name, review_type=review_type)
                    .order_by(ReviewRecord.reviewed_at.desc())
                    .first()
                )

                review_interval = self.config.get("robustness", {}).get(
                    f"{review_type}_interval_hours", 48
                )
                if latest:
                    reviewed_at = latest.reviewed_at
                    if reviewed_at.tzinfo is None:
                        reviewed_at = reviewed_at.replace(tzinfo=timezone.utc)
                    hours_since = (
                        datetime.now(timezone.utc) - reviewed_at
                    ).total_seconds() / 3600
                    if hours_since < review_interval:
                        continue

                findings = self.review_layer(
                    layer_db.name,
                    file_path,
                    review_type,
                    detection_rate=layer_db.effectiveness_score,
                )

                if findings:
                    report["reviews"].append({
                        "layer": layer_db.name,
                        "type": review_type,
                        "findings": findings,
                    })

                    # Auto-fix non-critical issues
                    severity_list = [
                        f.get("severity", "info") for f in findings.get("findings", [])
                    ]
                    if severity_list and "critical" not in severity_list:
                        fixed = self.auto_fix(layer_db.name, file_path, findings)
                        if fixed:
                            report["auto_fixes"].append(layer_db.name)

        logger.info(
            "Periodic review complete",
            extra={"extra_data": {
                "reviews_run": len(report["reviews"]),
                "auto_fixes": len(report["auto_fixes"]),
            }},
        )
        return report
