"""Report generation for threat analysis, test cycles, and system dashboards."""

import json
from datetime import datetime, timezone

from src.db.models import ClassifiedThreat, TestRun
from src.db.result_store import ResultStore
from src.db.threat_store import ThreatStore
from src.utils.logging import get_logger

logger = get_logger()


class ReportGenerator:
    """Generates Markdown reports from threat data and test results."""

    def __init__(self, result_store: ResultStore, threat_store: ThreatStore) -> None:
        self.result_store = result_store
        self.threat_store = threat_store

    def generate_threat_report(self, threat_id: str) -> str:
        """Generate a Markdown report for a single classified threat.

        Args:
            threat_id: The ID of the classified threat.

        Returns:
            A Markdown-formatted report string.
        """
        # Find the threat
        all_threats = self.threat_store.get_all_classified()
        threat = next((t for t in all_threats if t.id == threat_id), None)
        if not threat:
            return f"# Threat Report\n\nThreat `{threat_id}` not found.\n"

        runs = self.result_store.get_runs_for_threat(threat_id)

        lines = [
            f"# Threat Report: {threat.category}",
            "",
            f"**Threat ID:** `{threat.id}`",
            f"**Category:** {threat.category}",
            f"**Severity:** {threat.severity}",
            f"**Status:** {threat.status}",
            f"**Classified at:** {threat.classified_at}",
            "",
            "## Attack Vector",
            "",
            threat.attack_vector or "No attack vector description available.",
            "",
            "## Affected Components",
            "",
        ]

        for component in threat.get_affected_components():
            lines.append(f"- {component}")

        lines.extend(["", "## Covered by Layers", ""])
        covered = threat.get_covered_by_layers()
        if covered:
            for layer in covered:
                lines.append(f"- {layer}")
        else:
            lines.append("- None")

        # Defense plan
        if threat.defense_plan:
            try:
                plan = json.loads(threat.defense_plan)
                lines.extend([
                    "",
                    "## Defense Plan",
                    "",
                    f"**Layer name:** {plan.get('layer_name', 'N/A')}",
                    f"**Type:** {plan.get('layer_type', 'N/A')}",
                    f"**Priority:** {plan.get('priority', 'N/A')}",
                    "",
                    "### Detection Rules",
                    "",
                ])
                for rule in plan.get("detection_rules", []):
                    lines.append(
                        f"- **{rule.get('rule_id', 'unnamed')}**: "
                        f"{rule.get('description', 'No description')} "
                        f"(type: {rule.get('pattern_type', 'unknown')}, "
                        f"target: {rule.get('target', 'unknown')})"
                    )
            except (json.JSONDecodeError, TypeError):
                lines.extend(["", "## Defense Plan", "", "Plan data is malformed."])

        # Test results
        lines.extend(["", "## Test Results", ""])
        if runs:
            lines.append(
                "| Run ID | Profile | Detection | Prevention | Exfiltration | Latency (ms) |"
            )
            lines.append("|--------|---------|-----------|------------|--------------|--------------|")
            for run in runs:
                lines.append(
                    f"| `{run.id[:8]}...` | {run.victim_profile} "
                    f"| {run.detection_rate:.1%} | {run.prevention_rate:.1%} "
                    f"| {run.exfiltration_rate:.1%} | {run.latency_overhead_ms:.1f} |"
                )
        else:
            lines.append("No test runs recorded for this threat.")

        return "\n".join(lines) + "\n"

    def generate_cycle_report(self, run_ids: list[str]) -> str:
        """Generate a Markdown summary of a full test cycle.

        Args:
            run_ids: List of TestRun IDs to include in the report.

        Returns:
            A Markdown-formatted cycle report string.
        """
        all_runs = self.result_store.get_latest_runs(limit=500)
        runs = [r for r in all_runs if r.id in set(run_ids)]

        if not runs:
            return "# Cycle Report\n\nNo test runs found for the given IDs.\n"

        # Compute aggregate metrics
        total = len(runs)
        avg_detection = sum(r.detection_rate or 0.0 for r in runs) / total
        avg_prevention = sum(r.prevention_rate or 0.0 for r in runs) / total
        avg_exfiltration = sum(r.exfiltration_rate or 0.0 for r in runs) / total
        avg_fp = sum(r.false_positive_rate or 0.0 for r in runs) / total
        avg_latency = sum(r.latency_overhead_ms or 0.0 for r in runs) / total

        # Group by threat
        threats_tested: set[str] = set()
        profiles_tested: set[str] = set()
        for run in runs:
            threats_tested.add(run.threat_id)
            profiles_tested.add(run.victim_profile)

        lines = [
            "# Test Cycle Report",
            "",
            f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
            f"**Total test runs:** {total}",
            f"**Threats tested:** {len(threats_tested)}",
            f"**Victim profiles tested:** {len(profiles_tested)}",
            "",
            "## Aggregate Metrics",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Average Detection Rate | {avg_detection:.1%} |",
            f"| Average Prevention Rate | {avg_prevention:.1%} |",
            f"| Average Exfiltration Rate | {avg_exfiltration:.1%} |",
            f"| Average False Positive Rate | {avg_fp:.1%} |",
            f"| Average Latency Overhead | {avg_latency:.1f} ms |",
            "",
            "## Individual Runs",
            "",
            "| Run ID | Threat | Profile | Detection | Prevention | Exfiltration |",
            "|--------|--------|---------|-----------|------------|--------------|",
        ]

        for run in runs:
            lines.append(
                f"| `{run.id[:8]}...` | `{run.threat_id[:8]}...` "
                f"| {run.victim_profile} "
                f"| {run.detection_rate:.1%} | {run.prevention_rate:.1%} "
                f"| {run.exfiltration_rate:.1%} |"
            )

        return "\n".join(lines) + "\n"

    def generate_dashboard(self) -> str:
        """Generate a full system dashboard in Markdown.

        Includes:
        - Total threats collected/classified
        - Defense layer coverage
        - Latest test results
        - Top unaddressed threats
        - Effectiveness trends

        Returns:
            A Markdown-formatted dashboard string.
        """
        # Gather data
        unclassified = self.threat_store.get_unclassified_threats()
        all_classified = self.threat_store.get_all_classified()
        active_layers = self.result_store.get_active_layers()
        latest_runs = self.result_store.get_latest_runs(limit=20)

        # Counts by status
        status_counts: dict[str, int] = {}
        for threat in all_classified:
            status = threat.status or "unknown"
            status_counts[status] = status_counts.get(status, 0) + 1

        # Counts by severity
        severity_counts: dict[str, int] = {}
        for threat in all_classified:
            sev = threat.severity or "unknown"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines = [
            "# AI Threat Defense Agent - Dashboard",
            "",
            f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
            "",
            "---",
            "",
            "## Threat Intelligence",
            "",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| Raw threats (unclassified) | {len(unclassified)} |",
            f"| Classified threats | {len(all_classified)} |",
        ]

        for status, count in sorted(status_counts.items()):
            lines.append(f"| Status: {status} | {count} |")

        lines.extend(["", "### Severity Distribution", ""])
        for severity in ["critical", "high", "medium", "low"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                lines.append(f"- **{severity}**: {count}")

        # Defense layer coverage
        lines.extend([
            "",
            "---",
            "",
            "## Defense Layer Coverage",
            "",
        ])

        if active_layers:
            lines.append(
                "| Layer | Priority | Categories | Effectiveness |"
            )
            lines.append("|-------|----------|------------|---------------|")
            for layer in active_layers:
                categories = ", ".join(layer.get_threat_categories())
                lines.append(
                    f"| {layer.name} | {layer.priority} "
                    f"| {categories} | {layer.effectiveness_score:.0%} |"
                )
        else:
            lines.append("No active defense layers.")

        # Category coverage analysis
        all_categories = {
            "prompt_injection", "data_exfiltration", "jailbreak",
            "tool_abuse", "context_manipulation", "privilege_escalation",
        }
        covered_categories: set[str] = set()
        for layer in active_layers:
            covered_categories.update(layer.get_threat_categories())
        uncovered = all_categories - covered_categories

        if uncovered:
            lines.extend(["", "### Uncovered Threat Categories", ""])
            for cat in sorted(uncovered):
                lines.append(f"- {cat}")

        # Latest test results
        lines.extend([
            "",
            "---",
            "",
            "## Latest Test Results",
            "",
        ])

        if latest_runs:
            lines.append(
                "| Run ID | Threat | Profile | Detection | Prevention "
                "| Exfiltration | Latency |"
            )
            lines.append(
                "|--------|--------|---------|-----------|------------"
                "|--------------|---------|"
            )
            for run in latest_runs[:10]:
                lines.append(
                    f"| `{run.id[:8]}...` | `{run.threat_id[:8]}...` "
                    f"| {run.victim_profile} "
                    f"| {run.detection_rate:.1%} | {run.prevention_rate:.1%} "
                    f"| {run.exfiltration_rate:.1%} | {run.latency_overhead_ms:.1f}ms |"
                )

            # Aggregate
            if latest_runs:
                total = len(latest_runs)
                avg_det = sum(r.detection_rate or 0.0 for r in latest_runs) / total
                avg_prev = sum(r.prevention_rate or 0.0 for r in latest_runs) / total
                avg_exf = sum(r.exfiltration_rate or 0.0 for r in latest_runs) / total
                lines.extend([
                    "",
                    f"**Average detection rate:** {avg_det:.1%}",
                    f"**Average prevention rate:** {avg_prev:.1%}",
                    f"**Average exfiltration rate:** {avg_exf:.1%}",
                ])
        else:
            lines.append("No test runs recorded yet.")

        # Top unaddressed threats
        lines.extend([
            "",
            "---",
            "",
            "## Top Unaddressed Threats",
            "",
        ])

        unaddressed = [
            t for t in all_classified
            if t.status in ("new", "planned") and not t.get_covered_by_layers()
        ]
        # Sort by severity priority
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        unaddressed.sort(key=lambda t: severity_order.get(t.severity, 4))

        if unaddressed:
            lines.append("| Threat ID | Category | Severity | Status |")
            lines.append("|-----------|----------|----------|--------|")
            for threat in unaddressed[:10]:
                lines.append(
                    f"| `{threat.id[:8]}...` | {threat.category} "
                    f"| {threat.severity} | {threat.status} |"
                )
        else:
            lines.append("All known threats are addressed or covered by defense layers.")

        # Effectiveness trends (based on latest runs sorted by time)
        lines.extend([
            "",
            "---",
            "",
            "## Effectiveness Trends",
            "",
        ])

        if len(latest_runs) >= 2:
            # Split runs into two halves for trend comparison
            mid = len(latest_runs) // 2
            recent_half = latest_runs[:mid]
            older_half = latest_runs[mid:]

            recent_det = sum(r.detection_rate or 0.0 for r in recent_half) / len(recent_half)
            older_det = sum(r.detection_rate or 0.0 for r in older_half) / len(older_half)
            det_delta = recent_det - older_det

            recent_prev = sum(r.prevention_rate or 0.0 for r in recent_half) / len(recent_half)
            older_prev = sum(r.prevention_rate or 0.0 for r in older_half) / len(older_half)
            prev_delta = recent_prev - older_prev

            def trend_arrow(delta: float) -> str:
                if delta > 0.01:
                    return "improving"
                elif delta < -0.01:
                    return "declining"
                return "stable"

            lines.extend([
                f"- Detection rate: {recent_det:.1%} ({trend_arrow(det_delta)}, "
                f"{det_delta:+.1%} vs previous)",
                f"- Prevention rate: {recent_prev:.1%} ({trend_arrow(prev_delta)}, "
                f"{prev_delta:+.1%} vs previous)",
            ])
        else:
            lines.append("Insufficient data for trend analysis (need at least 2 test runs).")

        return "\n".join(lines) + "\n"
