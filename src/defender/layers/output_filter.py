"""Output filtering defense layer for detecting leaked sensitive data."""

import re

from src.defender.layers.base import (
    BaseDefenseLayer,
    DefenseContext,
    DefenseResult,
    DetectionRule,
)
from src.utils.logging import get_logger

logger = get_logger()

# Each rule: (name, pattern, description, severity, sensitivity_weight)
_SENSITIVE_PATTERNS: list[tuple[str, str, str, str, float]] = [
    # --- API keys and tokens ---
    (
        "aws_access_key",
        r"(?<![A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])",
        "AWS Access Key ID",
        "critical",
        1.0,
    ),
    (
        "aws_secret_key",
        r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
        "Potential AWS Secret Access Key (40-char base64)",
        "high",
        0.5,
    ),
    (
        "generic_api_key",
        r"(?i)(api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?",
        "Generic API key assignment pattern",
        "high",
        0.9,
    ),
    (
        "bearer_token",
        r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*",
        "Bearer authentication token",
        "high",
        0.9,
    ),
    (
        "github_token",
        r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
        "GitHub personal access token",
        "critical",
        1.0,
    ),
    (
        "slack_token",
        r"xox[bposatr]-[0-9]+-[A-Za-z0-9-]+",
        "Slack API token",
        "critical",
        1.0,
    ),
    # --- Credentials ---
    (
        "password_assignment",
        r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?",
        "Hardcoded password assignment",
        "critical",
        0.85,
    ),
    (
        "connection_string",
        r"(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s]{10,}",
        "Database / service connection string with potential credentials",
        "critical",
        0.95,
    ),
    # --- PII: Social Security Numbers ---
    (
        "ssn",
        r"\b\d{3}-\d{2}-\d{4}\b",
        "US Social Security Number pattern",
        "critical",
        1.0,
    ),
    # --- PII: Credit card numbers ---
    (
        "credit_card_visa",
        r"\b4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
        "Visa credit card number",
        "critical",
        1.0,
    ),
    (
        "credit_card_mastercard",
        r"\b5[1-5][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
        "Mastercard credit card number",
        "critical",
        1.0,
    ),
    (
        "credit_card_amex",
        r"\b3[47][0-9]{2}[\s-]?[0-9]{6}[\s-]?[0-9]{5}\b",
        "American Express credit card number",
        "critical",
        1.0,
    ),
    # --- Private keys ---
    (
        "private_key_pem",
        r"-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
        "PEM-encoded private key header",
        "critical",
        1.0,
    ),
    # --- Internal URLs / infrastructure ---
    (
        "internal_url",
        r"(?i)https?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3})[:/]?[^\s]*",
        "Internal / private network URL",
        "high",
        0.7,
    ),
    (
        "internal_hostname",
        r"(?i)https?://[a-z0-9-]+\.(?:internal|local|corp|intranet|private)\b[^\s]*",
        "Internal hostname pattern",
        "high",
        0.7,
    ),
    # --- Email addresses (potential PII leakage) ---
    (
        "email_address",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "Email address (potential PII leakage)",
        "medium",
        0.3,
    ),
]


class OutputFilter(BaseDefenseLayer):
    """Scans agent output for leaked sensitive data patterns.

    Priority: 50 (runs late in the pipeline, after agent processing).
    """

    name: str = "output_filter"
    priority: int = 50
    threat_categories: list[str] = ["data_exfiltration", "context_manipulation"]

    BLOCK_THRESHOLD: float = 0.80
    FLAG_THRESHOLD: float = 0.35

    def __init__(
        self,
        extra_patterns: list[tuple[str, str, str, str, float]] | None = None,
        block_threshold: float | None = None,
        flag_threshold: float | None = None,
    ) -> None:
        self._patterns = list(_SENSITIVE_PATTERNS)
        if extra_patterns:
            self._patterns.extend(extra_patterns)
        if block_threshold is not None:
            self.BLOCK_THRESHOLD = block_threshold
        if flag_threshold is not None:
            self.FLAG_THRESHOLD = flag_threshold

        self._compiled: list[tuple[str, re.Pattern[str], str, str, float]] = []
        for name, pattern, desc, severity, weight in self._patterns:
            try:
                self._compiled.append((name, re.compile(pattern), desc, severity, weight))
            except re.error as exc:
                logger.warning(
                    "Failed to compile output filter rule",
                    extra={"extra_data": {"rule": name, "error": str(exc)}},
                )

    def _redact(self, text: str, matches: list[tuple[str, re.Match[str]]]) -> str:
        """Produce a redacted version of the text, replacing matched spans."""
        if not matches:
            return text

        # Collect all spans to redact, merge overlapping ones.
        spans: list[tuple[int, int, str]] = []
        for rule_name, match in matches:
            spans.append((match.start(), match.end(), rule_name))
        spans.sort(key=lambda s: s[0])

        parts: list[str] = []
        cursor = 0
        for start, end, rule_name in spans:
            if start < cursor:
                continue
            parts.append(text[cursor:start])
            parts.append(f"[REDACTED:{rule_name}]")
            cursor = end
        parts.append(text[cursor:])
        return "".join(parts)

    async def inspect(self, data: DefenseContext) -> DefenseResult:
        text = data.output_text
        if not text:
            return DefenseResult(action="pass", confidence=1.0)

        matched_rules: list[tuple[str, str, str, float]] = []
        all_matches: list[tuple[str, re.Match[str]]] = []
        max_weight: float = 0.0

        for rule_name, compiled, desc, severity, weight in self._compiled:
            found = list(compiled.finditer(text))
            if found:
                matched_rules.append((rule_name, desc, severity, weight))
                max_weight = max(max_weight, weight)
                for m in found:
                    all_matches.append((rule_name, m))

        if not matched_rules:
            return DefenseResult(action="pass", confidence=1.0)

        # Sensitivity score: highest weight dominates, count adds minor boost.
        count_boost = min(len(matched_rules) * 0.05, 0.2)
        composite = min(max_weight + count_boost, 1.0)

        if composite >= self.BLOCK_THRESHOLD:
            action = "block"
        elif composite >= self.FLAG_THRESHOLD:
            action = "flag"
        else:
            action = "pass"

        redacted = self._redact(text, all_matches) if action != "pass" else None
        rule_names = [r[0] for r in matched_rules]
        reason = f"Sensitive data detected: {', '.join(rule_names)}; score={composite:.2f}"

        if action != "pass":
            logger.info(
                "OutputFilter triggered",
                extra={
                    "extra_data": {
                        "action": action,
                        "score": round(composite, 4),
                        "matched_rules": rule_names,
                        "match_count": len(all_matches),
                    }
                },
            )

        return DefenseResult(
            action=action,
            reason=reason,
            modified_text=redacted,
            confidence=composite,
        )

    def get_rules(self) -> list[DetectionRule]:
        return [
            DetectionRule(name=name, pattern=pattern, description=desc, severity=severity)
            for name, pattern, desc, severity, _weight in self._patterns
        ]
