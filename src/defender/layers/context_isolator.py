"""Context isolation defense layer for validating message boundaries."""

import re

from src.defender.layers.base import (
    BaseDefenseLayer,
    DefenseContext,
    DefenseResult,
    DetectionRule,
)
from src.utils.logging import get_logger

logger = get_logger()

# Maximum allowed context entries before we consider it a stuffing attempt.
_MAX_CONTEXT_ENTRIES = 100

# Maximum total character length across all context messages.
_MAX_CONTEXT_CHARS = 500_000

# Patterns that, when found inside a user message, indicate an attempt
# to impersonate system-level messages.
_SYSTEM_IMPERSONATION_RULES: list[tuple[str, str, str, str, float]] = [
    (
        "system_role_injection",
        r'(?i)\{\s*"role"\s*:\s*"system"',
        "JSON-formatted system role injection inside user content",
        "critical",
        1.0,
    ),
    (
        "system_tag_injection",
        r"(?i)<\|?system\|?>|<system_message>|\[SYSTEM\]|\[system\]",
        "System message tag injection in user input",
        "critical",
        1.0,
    ),
    (
        "assistant_impersonation",
        r'(?i)\{\s*"role"\s*:\s*"assistant"',
        "JSON-formatted assistant role injection inside user content",
        "high",
        0.8,
    ),
    (
        "hidden_instruction_block",
        r"(?i)<!--\s*(system|instruction|hidden|secret)\b[^>]*-->",
        "HTML comment disguised as hidden instruction block",
        "high",
        0.85,
    ),
    (
        "context_boundary_break",
        r"(?i)(END\s+OF\s+(SYSTEM|CONTEXT|INSTRUCTIONS))"
        r"|(BEGIN\s+(USER|NEW)\s+(CONTEXT|SESSION|CONVERSATION))",
        "Fake context boundary markers in user input",
        "high",
        0.8,
    ),
    (
        "message_array_injection",
        r'(?i)\[\s*\{\s*"role"\s*:',
        "Attempt to inject a full messages array structure",
        "critical",
        0.95,
    ),
]


class ContextIsolator(BaseDefenseLayer):
    """Validates context boundaries and prevents context manipulation attacks.

    Priority: 20 (runs early, right after input validation).
    """

    name: str = "context_isolator"
    priority: int = 20
    threat_categories: list[str] = [
        "context_manipulation",
        "privilege_escalation",
    ]

    BLOCK_THRESHOLD: float = 0.80
    FLAG_THRESHOLD: float = 0.45

    def __init__(
        self,
        max_context_entries: int = _MAX_CONTEXT_ENTRIES,
        max_context_chars: int = _MAX_CONTEXT_CHARS,
        extra_rules: list[tuple[str, str, str, str, float]] | None = None,
    ) -> None:
        self.max_context_entries = max_context_entries
        self.max_context_chars = max_context_chars

        self._rules = list(_SYSTEM_IMPERSONATION_RULES)
        if extra_rules:
            self._rules.extend(extra_rules)

        self._compiled: list[tuple[str, re.Pattern[str], str, str, float]] = []
        for rule_name, pattern, desc, severity, weight in self._rules:
            try:
                self._compiled.append((rule_name, re.compile(pattern), desc, severity, weight))
            except re.error as exc:
                logger.warning(
                    "Failed to compile context isolator rule",
                    extra={"extra_data": {"rule": rule_name, "error": str(exc)}},
                )

    def _check_context_integrity(self, context: list[dict]) -> list[str]:
        """Validate structural integrity of the context window.

        Returns a list of issue descriptions (empty if clean).
        """
        issues: list[str] = []

        if len(context) > self.max_context_entries:
            issues.append(
                f"Context entry count ({len(context)}) exceeds limit ({self.max_context_entries})"
            )

        total_chars = 0
        user_system_transitions = 0
        prev_role: str | None = None

        for idx, msg in enumerate(context):
            role = msg.get("role", "")
            content = msg.get("content", "")

            if isinstance(content, str):
                total_chars += len(content)

            # Detect user messages masquerading with system role.
            if role not in ("system", "user", "assistant", "tool"):
                issues.append(f"Message {idx} has unexpected role: '{role}'")

            # Track role transitions; excessive system->user->system swaps are suspicious.
            if prev_role == "user" and role == "system":
                user_system_transitions += 1
            prev_role = role

        if total_chars > self.max_context_chars:
            issues.append(
                f"Total context size ({total_chars} chars) exceeds limit ({self.max_context_chars})"
            )

        if user_system_transitions > 2:
            issues.append(
                f"Suspicious role transitions: {user_system_transitions} user->system switches"
            )

        return issues

    def _scan_user_messages_for_impersonation(
        self, context: list[dict], input_text: str,
    ) -> tuple[list[str], float]:
        """Scan user messages and the current input for system impersonation patterns.

        Returns (matched_rule_names, max_weight).
        """
        # Combine all user-role content plus the current input.
        user_texts: list[str] = [input_text] if input_text else []
        for msg in context:
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    user_texts.append(content)

        matched: list[str] = []
        max_weight: float = 0.0

        combined = "\n".join(user_texts)
        for rule_name, compiled, _desc, _severity, weight in self._compiled:
            if compiled.search(combined):
                matched.append(rule_name)
                max_weight = max(max_weight, weight)

        return matched, max_weight

    async def inspect(self, data: DefenseContext) -> DefenseResult:
        issues: list[str] = []
        threat_score: float = 0.0

        # 1. Structural integrity checks.
        if data.context:
            integrity_issues = self._check_context_integrity(data.context)
            if integrity_issues:
                issues.extend(integrity_issues)
                # Each structural issue adds to the threat score.
                threat_score += min(len(integrity_issues) * 0.25, 0.6)

        # 2. Impersonation pattern scanning.
        matched_rules, pattern_score = self._scan_user_messages_for_impersonation(
            data.context, data.input_text,
        )
        if matched_rules:
            issues.extend([f"Impersonation pattern: {r}" for r in matched_rules])

        # Composite: pattern matches dominate.
        composite = max(threat_score, pattern_score)
        composite = min(composite, 1.0)

        if composite >= self.BLOCK_THRESHOLD:
            action = "block"
        elif composite >= self.FLAG_THRESHOLD:
            action = "flag"
        else:
            action = "pass"

        reason = None
        if issues:
            reason = "; ".join(issues) + f" (score={composite:.2f})"

        if action != "pass":
            logger.info(
                "ContextIsolator triggered",
                extra={
                    "extra_data": {
                        "action": action,
                        "score": round(composite, 4),
                        "issues": issues,
                    }
                },
            )

        return DefenseResult(
            action=action,
            reason=reason,
            confidence=composite,
        )

    def get_rules(self) -> list[DetectionRule]:
        return [
            DetectionRule(name=name, pattern=pattern, description=desc, severity=severity)
            for name, pattern, desc, severity, _weight in self._rules
        ]
