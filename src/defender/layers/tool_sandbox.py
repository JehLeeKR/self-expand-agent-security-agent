"""Tool sandboxing defense layer for validating and constraining tool calls."""

import re

from src.defender.layers.base import (
    BaseDefenseLayer,
    DefenseContext,
    DefenseResult,
    DetectionRule,
)
from src.utils.logging import get_logger

logger = get_logger()

# Default allowed tools.  An empty set means *all* tools are allowed (open mode).
_DEFAULT_ALLOWED_TOOLS: set[str] = set()

# File path patterns considered sensitive.
_SENSITIVE_PATH_PATTERNS: list[tuple[str, str, str, str, float]] = [
    (
        "ssh_keys",
        r"(?i)(/\.ssh/|\\\.ssh\\)",
        "Access to SSH key directory",
        "critical",
        1.0,
    ),
    (
        "credentials_file",
        r"(?i)(credentials|\.env|\.netrc|\.pgpass|\.my\.cnf|\.aws/credentials|\.npmrc)",
        "Access to credentials / secret configuration file",
        "critical",
        1.0,
    ),
    (
        "etc_shadow",
        r"(?i)/etc/(shadow|passwd|sudoers)",
        "Access to system authentication files",
        "critical",
        1.0,
    ),
    (
        "private_key_file",
        r"(?i)\.(pem|key|pfx|p12|jks)$",
        "Access to private key / certificate store file",
        "critical",
        0.95,
    ),
    (
        "history_file",
        r"(?i)(\.bash_history|\.zsh_history|\.python_history|\.psql_history)",
        "Access to shell / tool history files",
        "high",
        0.8,
    ),
    (
        "sensitive_system_dir",
        r"(?i)^/(proc|sys|dev)/",
        "Access to sensitive Linux system directories",
        "high",
        0.7,
    ),
    (
        "home_dir_traversal",
        r"\.\./\.\./",
        "Directory traversal pattern (../../)",
        "high",
        0.8,
    ),
    (
        "windows_sensitive",
        r"(?i)(SAM|NTDS\.dit|SYSTEM|SECURITY)$",
        "Access to Windows credential stores",
        "critical",
        1.0,
    ),
]

# Suspicious tool-call argument patterns.
_SUSPICIOUS_ARG_PATTERNS: list[tuple[str, str, str, str, float]] = [
    (
        "shell_injection",
        r"(?i)(;\s*(rm|curl|wget|nc|ncat|bash|sh|python|perl|ruby)\b)"
        r"|(\|\s*(bash|sh|nc|ncat)\b)"
        r"|(`[^`]+`)"
        r"|(\$\([^)]+\))",
        "Shell command injection in tool arguments",
        "critical",
        1.0,
    ),
    (
        "url_exfiltration",
        r"(?i)(curl|wget|fetch|http\.get)\s+https?://[^\s]+",
        "Potential data exfiltration via URL fetch in arguments",
        "high",
        0.85,
    ),
    (
        "base64_payload",
        r"(?i)base64\s+(-d|--decode)|echo\s+[A-Za-z0-9+/=]{40,}\s*\|",
        "Base64-encoded payload execution pattern",
        "high",
        0.8,
    ),
]


class ToolSandbox(BaseDefenseLayer):
    """Validates tool calls against allowlists, detects suspicious paths and arguments.

    Priority: 30 (runs after input validation and context isolation).
    """

    name: str = "tool_sandbox"
    priority: int = 30
    threat_categories: list[str] = [
        "tool_abuse",
        "data_exfiltration",
        "privilege_escalation",
    ]

    BLOCK_THRESHOLD: float = 0.80
    FLAG_THRESHOLD: float = 0.40

    def __init__(
        self,
        allowed_tools: set[str] | None = None,
        extra_path_rules: list[tuple[str, str, str, str, float]] | None = None,
        extra_arg_rules: list[tuple[str, str, str, str, float]] | None = None,
        max_tool_calls: int = 20,
    ) -> None:
        self.allowed_tools: set[str] = allowed_tools if allowed_tools is not None else set(_DEFAULT_ALLOWED_TOOLS)
        self.max_tool_calls = max_tool_calls

        path_rules = list(_SENSITIVE_PATH_PATTERNS)
        if extra_path_rules:
            path_rules.extend(extra_path_rules)

        arg_rules = list(_SUSPICIOUS_ARG_PATTERNS)
        if extra_arg_rules:
            arg_rules.extend(extra_arg_rules)

        self._path_compiled: list[tuple[str, re.Pattern[str], str, str, float]] = []
        self._arg_compiled: list[tuple[str, re.Pattern[str], str, str, float]] = []

        for rule_name, pattern, desc, severity, weight in path_rules:
            try:
                self._path_compiled.append((rule_name, re.compile(pattern), desc, severity, weight))
            except re.error as exc:
                logger.warning("Bad path rule", extra={"extra_data": {"rule": rule_name, "error": str(exc)}})

        for rule_name, pattern, desc, severity, weight in arg_rules:
            try:
                self._arg_compiled.append((rule_name, re.compile(pattern), desc, severity, weight))
            except re.error as exc:
                logger.warning("Bad arg rule", extra={"extra_data": {"rule": rule_name, "error": str(exc)}})

    def _extract_strings(self, obj: object) -> list[str]:
        """Recursively extract all string values from a nested dict/list structure."""
        strings: list[str] = []
        if isinstance(obj, str):
            strings.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                strings.extend(self._extract_strings(v))
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                strings.extend(self._extract_strings(v))
        return strings

    def _check_tool_allowlist(self, tool_calls: list[dict]) -> list[str]:
        """Check if any tool calls use tools not on the allowlist."""
        if not self.allowed_tools:
            return []  # Open mode -- all tools allowed.

        violations: list[str] = []
        for call in tool_calls:
            tool_name = call.get("name") or call.get("tool") or call.get("function", "")
            if tool_name and tool_name not in self.allowed_tools:
                violations.append(f"Unauthorized tool: {tool_name}")
        return violations

    def _scan_paths(self, tool_calls: list[dict]) -> tuple[list[str], float]:
        """Scan tool call arguments for sensitive file paths."""
        all_strings = []
        for call in tool_calls:
            args = call.get("arguments") or call.get("args") or call.get("input", {})
            all_strings.extend(self._extract_strings(args))

        matched: list[str] = []
        max_weight: float = 0.0

        combined = " ".join(all_strings)
        for rule_name, compiled, _desc, _severity, weight in self._path_compiled:
            if compiled.search(combined):
                matched.append(rule_name)
                max_weight = max(max_weight, weight)

        return matched, max_weight

    def _scan_args(self, tool_calls: list[dict]) -> tuple[list[str], float]:
        """Scan tool call arguments for suspicious command patterns."""
        all_strings = []
        for call in tool_calls:
            args = call.get("arguments") or call.get("args") or call.get("input", {})
            all_strings.extend(self._extract_strings(args))

        matched: list[str] = []
        max_weight: float = 0.0

        combined = " ".join(all_strings)
        for rule_name, compiled, _desc, _severity, weight in self._arg_compiled:
            if compiled.search(combined):
                matched.append(rule_name)
                max_weight = max(max_weight, weight)

        return matched, max_weight

    async def inspect(self, data: DefenseContext) -> DefenseResult:
        tool_calls = data.tool_calls
        if not tool_calls:
            return DefenseResult(action="pass", confidence=1.0)

        issues: list[str] = []
        max_score: float = 0.0

        # 1. Allowlist check.
        allowlist_violations = self._check_tool_allowlist(tool_calls)
        if allowlist_violations:
            issues.extend(allowlist_violations)
            max_score = max(max_score, 0.9)

        # 2. Excessive tool calls.
        if len(tool_calls) > self.max_tool_calls:
            issues.append(
                f"Excessive tool calls: {len(tool_calls)} (limit {self.max_tool_calls})"
            )
            max_score = max(max_score, 0.6)

        # 3. Sensitive path scanning.
        path_matches, path_score = self._scan_paths(tool_calls)
        if path_matches:
            issues.extend([f"Sensitive path: {r}" for r in path_matches])
            max_score = max(max_score, path_score)

        # 4. Suspicious argument scanning.
        arg_matches, arg_score = self._scan_args(tool_calls)
        if arg_matches:
            issues.extend([f"Suspicious argument: {r}" for r in arg_matches])
            max_score = max(max_score, arg_score)

        composite = min(max_score, 1.0)

        if not issues:
            return DefenseResult(action="pass", confidence=1.0)

        if composite >= self.BLOCK_THRESHOLD:
            action = "block"
        elif composite >= self.FLAG_THRESHOLD:
            action = "flag"
        else:
            action = "pass"

        reason = "; ".join(issues) + f" (score={composite:.2f})"

        if action != "pass":
            logger.info(
                "ToolSandbox triggered",
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
        rules: list[DetectionRule] = []
        for name, pattern, desc, severity, _w in _SENSITIVE_PATH_PATTERNS:
            rules.append(DetectionRule(name=name, pattern=pattern, description=desc, severity=severity))
        for name, pattern, desc, severity, _w in _SUSPICIOUS_ARG_PATTERNS:
            rules.append(DetectionRule(name=name, pattern=pattern, description=desc, severity=severity))
        return rules
