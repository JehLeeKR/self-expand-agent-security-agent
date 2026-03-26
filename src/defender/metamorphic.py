"""Metamorphic defense engine — defenses that evolve their own detection patterns.

Attackers profile defenses by testing specific payloads and observing responses.
Static detection patterns become known and eventually bypassed. Metamorphic
defenses counter this by periodically transforming their detection logic while
maintaining equivalent security coverage.

Metamorphic techniques:
1. **Pattern rotation**: Swap between equivalent regex families
2. **Signature evolution**: Evolve patterns based on new attack samples
3. **Structure morphing**: Restructure detection logic (reorder checks,
   change scoring weights, swap algorithms)
4. **Decoy injection**: Add benign-looking patterns that detect reconnaissance

Architecture (Part 2 — Claude Code CLI Implementation):
Claude Code CLI rewrites defense layer code with semantically equivalent but
syntactically different detection logic. The security properties are preserved
but the exact patterns, thresholds, and code structure change — making it
impossible for attackers to reliably fingerprint the defense.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from src.db.models import MetamorphicEvent
from src.db.result_store import ResultStore
from src.utils.claude_code import ClaudeCode
from src.utils.logging import get_logger

logger = get_logger()

_MORPH_PROMPT = """\
You are performing a METAMORPHIC TRANSFORMATION of a defense layer.

The goal: rewrite the detection logic so that it is functionally equivalent
(catches the same attacks) but structurally and syntactically different
(attackers cannot fingerprint it by testing specific patterns).

## File to Transform: {file_path}
## Layer Name: {layer_name}
## Current Effectiveness: {effectiveness:.1%}

## Transformation Type: {morph_type}

## Instructions for "{morph_type}" Transformation:
{morph_instructions}

## Critical Rules
1. Read the current file FIRST — understand exactly what it detects
2. The transformed version MUST detect the same threat categories
3. The transformed version MUST maintain similar effectiveness
4. The transformed version MUST have different:
   - Regex patterns (equivalent but different syntax)
   - Variable names and internal structure
   - Scoring algorithm implementation (same results, different code)
   - Detection order and flow
5. Keep the same: class name, layer name, priority, base class, interface
6. Add comment: `# Metamorphic transform: {morph_type} at {{timestamp}}`
7. Verify: python3 -m py_compile {file_path}
"""

_MORPH_TYPES = {
    "pattern_rotate": (
        "Replace all regex patterns with functionally equivalent alternatives. "
        "For example: `r'ignore.*previous'` → `r'(?:disregard|ignore|forget)\\s+.*?(?:prior|previous|above)'`. "
        "Use different regex syntax (character classes vs alternation, possessive vs greedy, etc). "
        "Reorder pattern families. Change pattern names and descriptions."
    ),
    "signature_evolve": (
        "Evolve detection signatures to cover new attack variants. Add patterns for: "
        "- Unicode homoglyph substitutions (е→e, а→a, ℎ→h) "
        "- Zero-width character injection "
        "- Base64/hex encoded payloads "
        "- Split-word attacks (ig nore prev ious) "
        "- Comment injection tricks "
        "Keep all existing detection capability while adding these new families."
    ),
    "structure_morph": (
        "Restructure the detection logic without changing what it detects: "
        "- Reorder the sequence of checks "
        "- Change from sequential scoring to parallel scoring (or vice versa) "
        "- Inline helper functions or extract them "
        "- Change data structures (dict → list of tuples, set → frozenset) "
        "- Use different Python idioms for the same operations "
        "- Change how confidence scores are computed (same results, different formula)"
    ),
    "decoy_injection": (
        "Add decoy detection patterns that identify reconnaissance behavior: "
        "- Patterns that detect when someone is systematically testing edge cases "
        "- Canary patterns that flag known defense-probing payloads "
        "- Honeypot rules that detect when payloads are designed to measure response "
        "- These MUST NOT increase false positive rate on legitimate inputs "
        "- Flag (don't block) reconnaissance attempts to track attacker behavior"
    ),
}


class MetamorphicEngine:
    """Periodically transforms defense layers to prevent attacker fingerprinting.

    Each transformation maintains functional equivalence while changing the
    syntactic structure of detection logic. This makes reverse-engineering
    defenses a moving target.
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
        self._morph_cycle_index = 0

    def _get_next_morph_type(self) -> str:
        """Cycle through morph types in order."""
        types = list(_MORPH_TYPES.keys())
        morph_type = types[self._morph_cycle_index % len(types)]
        self._morph_cycle_index += 1
        return morph_type

    def transform_layer(
        self,
        layer_name: str,
        file_path: str,
        effectiveness: float = 0.0,
        morph_type: str | None = None,
    ) -> dict | None:
        """Apply a metamorphic transformation to a defense layer.

        Args:
            layer_name: Name of the defense layer
            file_path: Path to the layer's Python file
            effectiveness: Current effectiveness score (for context)
            morph_type: Specific transformation type, or None for auto-cycle

        Returns:
            Transformation result dict, or None on failure.
        """
        if morph_type is None:
            morph_type = self._get_next_morph_type()

        morph_instructions = _MORPH_TYPES.get(morph_type, _MORPH_TYPES["pattern_rotate"])

        logger.info(
            "Starting metamorphic transformation",
            extra={"extra_data": {
                "layer": layer_name,
                "morph_type": morph_type,
            }},
        )

        prompt = _MORPH_PROMPT.format(
            file_path=file_path,
            layer_name=layer_name,
            effectiveness=effectiveness,
            morph_type=morph_type,
            morph_instructions=morph_instructions,
        )

        result = self.claude_code.implement(prompt, file_path)
        if not result.get("success"):
            logger.error(
                "Metamorphic transformation failed",
                extra={"extra_data": {
                    "layer": layer_name,
                    "morph_type": morph_type,
                    "error": str(result.get("output", ""))[:300],
                }},
            )
            return None

        verify = self.claude_code.verify_code(file_path)
        if not verify.get("success"):
            logger.error(
                "Transformed code failed verification",
                extra={"extra_data": {"layer": layer_name}},
            )
            return None

        # Record event
        event = MetamorphicEvent(
            id=str(uuid.uuid4()),
            layer_name=layer_name,
            event_type=morph_type,
            patterns_before=json.dumps({"pre_transform": True}),
            patterns_after=json.dumps({"post_transform": True, "type": morph_type}),
            effectiveness_before=effectiveness,
            effectiveness_after=0.0,  # Will be measured in next test cycle
        )
        self.session.add(event)
        self.session.commit()

        logger.info(
            "Metamorphic transformation complete",
            extra={"extra_data": {
                "layer": layer_name,
                "morph_type": morph_type,
            }},
        )

        return {
            "layer": layer_name,
            "morph_type": morph_type,
            "status": "transformed",
        }

    def run(self) -> list[dict]:
        """Run metamorphic transformations on eligible layers.

        Transforms layers that have been stable (not recently adapted or
        transformed) and have sufficient test history.

        Returns list of transformation results.
        """
        active_layers = self.result_store.get_active_layers()
        results = []

        for layer_db in active_layers:
            # Check if recently transformed (within last 24h)
            recent = (
                self.session.query(MetamorphicEvent)
                .filter_by(layer_name=layer_db.name)
                .order_by(MetamorphicEvent.rotated_at.desc())
                .first()
            )
            if recent:
                rotated_at = recent.rotated_at
                if rotated_at.tzinfo is None:
                    rotated_at = rotated_at.replace(tzinfo=timezone.utc)
                hours_since = (
                    datetime.now(timezone.utc) - rotated_at
                ).total_seconds() / 3600
                morph_interval = self.config.get("robustness", {}).get(
                    "metamorphic_interval_hours", 48
                )
                if hours_since < morph_interval:
                    continue

            # Resolve file path
            file_path = layer_db.module_path
            if "." in file_path and not file_path.endswith(".py"):
                parts = file_path.rsplit(".", 1)
                file_path = parts[0].replace(".", "/") + ".py"

            result = self.transform_layer(
                layer_db.name,
                file_path,
                layer_db.effectiveness_score,
            )
            if result:
                results.append(result)

        logger.info(
            "Metamorphic cycle complete",
            extra={"extra_data": {"transformed": len(results)}},
        )
        return results
