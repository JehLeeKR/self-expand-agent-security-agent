"""Input validation defense layer for detecting prompt injection and jailbreak attempts."""

import re
from typing import Literal

from src.defender.layers.base import (
    BaseDefenseLayer,
    DefenseContext,
    DefenseResult,
    DetectionRule,
)
from src.utils.logging import get_logger

logger = get_logger()

# Default detection rules -- each tuple is (name, pattern, description, severity, weight).
# Weight controls how much a single match contributes to the overall threat score.
_DEFAULT_RULES: list[tuple[str, str, str, str, float]] = [
    # --- Delimiter injection ---
    (
        "delimiter_injection",
        r"(?i)```\s*system\b|<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|<<\s*SYS\s*>>",
        "Detects injected chat-template delimiters (ChatML, Llama-style, markdown system blocks)",
        "high",
        0.9,
    ),
    # --- System prompt extraction ---
    (
        "system_prompt_extraction",
        r"(?i)(ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?|directives?))"
        r"|(repeat\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?))"
        r"|(what\s+(are|were)\s+your\s+(initial|original|system)\s+(instructions?|prompts?))"
        r"|(show\s+me\s+your\s+(system|hidden|secret)\s+(prompt|message|instructions?))",
        "Detects attempts to extract or override the system prompt",
        "critical",
        1.0,
    ),
    # --- Instruction override ---
    (
        "instruction_override",
        r"(?i)(you\s+are\s+now\s+(a|an|in)\b)"
        r"|(new\s+instructions?\s*:)"
        r"|(forget\s+(everything|all|your)\b)"
        r"|(disregard\s+(all|any|the|previous)\b)"
        r"|(override\s+(mode|protocol|safety|instructions?))",
        "Detects attempts to override agent instructions via role-play or direct commands",
        "critical",
        1.0,
    ),
    # --- Role-playing / persona attacks ---
    (
        "roleplay_attack",
        r"(?i)(pretend\s+(you\s+are|to\s+be)\b)"
        r"|(act\s+as\s+(if\s+you\s+are\s+)?a\b)"
        r"|(you\s+must\s+(obey|comply|follow)\b)"
        r"|(entering\s+(developer|god|admin|sudo|root|DAN)\s+mode)",
        "Detects role-playing attacks designed to bypass safety constraints",
        "high",
        0.8,
    ),
    # --- Encoding tricks ---
    (
        "encoding_tricks",
        r"(?i)(base64\s*:\s*[A-Za-z0-9+/=]{20,})"
        r"|(%[0-9a-fA-F]{2}){5,}"
        r"|(\\x[0-9a-fA-F]{2}){5,}"
        r"|(\\u[0-9a-fA-F]{4}){3,}"
        r"|(rot13|base64_decode|atob|btoa)\s*\(",
        "Detects encoded payloads used to bypass text-based filters",
        "medium",
        0.6,
    ),
    # --- Multi-language obfuscation ---
    (
        "multilingual_obfuscation",
        r"(?i)(translate\s+the\s+following\s+and\s+(execute|run|follow))"
        r"|(in\s+(hex|binary|morse|pig\s+latin)\s*[:,])",
        "Detects attempts to use translation or encoding as an obfuscation layer",
        "medium",
        0.5,
    ),
    # --- Payload separator / context splitting ---
    (
        "context_splitting",
        r"(?i)(={5,})"
        r"|(-{5,}\s*(new|end|begin|start)\s*(section|prompt|context|conversation))"
        r"|(BEGINPROMPT|ENDPROMPT|END_OF_SYSTEM)"
        r"|(---\s*USER\s*---)",
        "Detects visual separators intended to trick the model into treating injected text as a new context",
        "high",
        0.7,
    ),
    # --- Indirect injection markers ---
    (
        "indirect_injection",
        r"(?i)(IMPORTANT:\s*ignore)"
        r"|(ASSISTANT:\s*Sure)"
        r"|(Human:\s*)"
        r"|(AI:\s*I\s+will)",
        "Detects indirect prompt injection markers embedded in external content",
        "high",
        0.75,
    ),
]


class InputValidator(BaseDefenseLayer):
    """Validates user input against known prompt injection and jailbreak patterns.

    Priority: 10 (runs first in the pipeline).
    """

    name: str = "input_validator"
    priority: int = 10
    threat_categories: list[str] = [
        "prompt_injection",
        "jailbreak",
        "context_manipulation",
    ]

    # Thresholds
    BLOCK_THRESHOLD: float = 0.85
    FLAG_THRESHOLD: float = 0.45

    def __init__(
        self,
        extra_rules: list[tuple[str, str, str, str, float]] | None = None,
        block_threshold: float | None = None,
        flag_threshold: float | None = None,
    ) -> None:
        self._rules = list(_DEFAULT_RULES)
        if extra_rules:
            self._rules.extend(extra_rules)
        if block_threshold is not None:
            self.BLOCK_THRESHOLD = block_threshold
        if flag_threshold is not None:
            self.FLAG_THRESHOLD = flag_threshold

        # Pre-compile patterns for performance.
        self._compiled: list[tuple[str, re.Pattern[str], str, str, float]] = []
        for name, pattern, desc, severity, weight in self._rules:
            try:
                self._compiled.append((name, re.compile(pattern), desc, severity, weight))
            except re.error as exc:
                logger.warning(
                    "Failed to compile detection rule",
                    extra={"extra_data": {"rule": name, "error": str(exc)}},
                )

    # --- Heuristic helpers --------------------------------------------------

    @staticmethod
    def _instruction_density_score(text: str) -> float:
        """Score based on density of imperative / command-like language."""
        imperative_markers = [
            "must", "shall", "should", "do not", "don't", "never", "always",
            "immediately", "override", "execute", "run", "perform", "output",
        ]
        words = text.lower().split()
        if not words:
            return 0.0
        hits = sum(1 for w in words if w in imperative_markers)
        return min(hits / max(len(words), 1) * 10, 1.0)

    @staticmethod
    def _suspicious_length_score(text: str) -> float:
        """Flag unusually long inputs that may be context-stuffing attempts."""
        length = len(text)
        if length > 15000:
            return 0.8
        if length > 8000:
            return 0.4
        if length > 4000:
            return 0.2
        return 0.0

    # --- Core inspection ----------------------------------------------------

    async def inspect(self, data: DefenseContext) -> DefenseResult:
        text = data.input_text
        if not text:
            return DefenseResult(action="pass", confidence=1.0)

        matched_rules: list[tuple[str, str, str, float]] = []
        max_weight: float = 0.0

        for rule_name, compiled, desc, severity, weight in self._compiled:
            if compiled.search(text):
                matched_rules.append((rule_name, desc, severity, weight))
                max_weight = max(max_weight, weight)

        # Combine regex score with heuristic scores.
        regex_score = max_weight if matched_rules else 0.0
        density_score = self._instruction_density_score(text)
        length_score = self._suspicious_length_score(text)

        # Weighted composite: regex matches dominate, heuristics contribute.
        composite = regex_score * 0.7 + density_score * 0.2 + length_score * 0.1

        if composite >= self.BLOCK_THRESHOLD:
            action: Literal["pass", "block", "flag"] = "block"
        elif composite >= self.FLAG_THRESHOLD:
            action = "flag"
        else:
            action = "pass"

        reason = None
        if matched_rules:
            names = [r[0] for r in matched_rules]
            reason = f"Matched rules: {', '.join(names)}; composite_score={composite:.2f}"

        if action != "pass":
            logger.info(
                "InputValidator triggered",
                extra={
                    "extra_data": {
                        "action": action,
                        "composite_score": round(composite, 4),
                        "matched_rules": [r[0] for r in matched_rules],
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
