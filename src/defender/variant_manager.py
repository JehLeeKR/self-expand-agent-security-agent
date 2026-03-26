"""Variant twin manager — maintains multiple implementations of the same defense.

Diversity is a core security principle. If an attacker reverse-engineers one
defense layer's detection patterns, variant twins ensure that alternative
implementations with different detection strategies remain effective.

Architecture (Part 2 — Claude Code CLI Implementation):
- Claude Code CLI generates N variant implementations per threat category
- Each variant uses a different detection strategy (regex, heuristic, LLM-based, etc.)
- The active variant is rotated periodically to prevent attacker fingerprinting
- Underperforming variants are regenerated, not just disabled

This is analogous to biological immune system diversity — multiple antibodies
for the same pathogen, each recognizing different epitopes.
"""

from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone
from pathlib import Path

from src.db.models import VariantGroup, VariantMember
from src.db.result_store import ResultStore
from src.defender.layer_registry import LayerRegistry
from src.utils.claude_code import ClaudeCode
from src.utils.logging import get_logger

logger = get_logger()

_VARIANT_STRATEGIES = [
    {
        "name": "regex_pattern",
        "description": "Pure regex-based detection with compiled patterns and composite scoring",
        "instruction": "Use only pre-compiled regex patterns. No external API calls. "
                       "Focus on syntactic pattern matching with multiple regex families.",
    },
    {
        "name": "heuristic_statistical",
        "description": "Statistical heuristics — entropy analysis, token distribution, anomaly scores",
        "instruction": "Use statistical methods: Shannon entropy, character distribution analysis, "
                       "n-gram frequency deviation, Zipf's law violation detection. No regex.",
    },
    {
        "name": "structural_analysis",
        "description": "AST/structural analysis of input — detects structural anomalies",
        "instruction": "Analyze structural properties: nested delimiter depth, instruction density, "
                       "role-switching frequency, context boundary violations. Use tree/graph analysis.",
    },
    {
        "name": "behavioral_fingerprint",
        "description": "Behavioral fingerprinting — tracks interaction patterns over time",
        "instruction": "Maintain a sliding window of recent interactions. Detect behavioral anomalies: "
                       "sudden topic shifts, escalating privilege requests, reconnaissance patterns. "
                       "Use state tracking across multiple inspect() calls.",
    },
    {
        "name": "ensemble_lightweight",
        "description": "Lightweight ensemble of multiple micro-detectors with voting",
        "instruction": "Implement 5+ independent micro-detectors, each checking one specific signal. "
                       "Use majority voting with weighted confidence. Each micro-detector must be "
                       "independently testable.",
    },
]

_VARIANT_IMPLEMENTATION_PROMPT = """\
You are implementing a VARIANT TWIN defense layer. This is one of multiple
independent implementations defending against the same threat category.

IMPORTANT: First read these files to understand the codebase patterns:
1. src/defender/layers/base.py — base classes to subclass
2. src/defender/layers/input_validator.py — reference implementation
3. Any existing variant files in src/defender/layers/ for this category

## Threat Category: {category}
## Variant Strategy: {strategy_name}
## Strategy Description: {strategy_description}
## Strategy Instruction: {strategy_instruction}

## Original Defense Plan
{defense_plan}

## Implementation Requirements
- File: {output_file}
- Subclass `BaseDefenseLayer` from `src.defender.layers.base`
- Class name: `{class_name}`
- Set `name = "{layer_name}"`
- Set appropriate `priority` and `threat_categories = ["{category}"]`
- MUST use the {strategy_name} strategy — do NOT fall back to simple regex
- Implement `async inspect(self, data: DefenseContext) -> DefenseResult`
- Implement `get_rules(self) -> list[DetectionRule]`
- Return 'block' (confidence >= 0.85), 'flag' (>= 0.45), 'pass' otherwise
- Production quality: type hints, docstrings, real detection logic
- This variant MUST be meaningfully different from other variants

After writing, verify: `python3 -m py_compile {output_file}`
"""


class VariantManager:
    """Manages variant twin defense implementations.

    For each threat category, maintains multiple independent implementations
    using different detection strategies. Rotates the active variant and
    regenerates underperformers.
    """

    def __init__(
        self,
        claude_code: ClaudeCode,
        layer_registry: LayerRegistry,
        result_store: ResultStore,
        config: dict | None = None,
    ) -> None:
        self.claude_code = claude_code
        self.layer_registry = layer_registry
        self.result_store = result_store
        self.config = config or {}
        self.output_dir = Path(
            self.config.get("layer_output_dir", "src/defender/layers")
        )
        self.variants_per_category = self.config.get(
            "robustness", {}
        ).get("variants_per_category", 3)
        self.session = result_store.session

    def _get_or_create_group(self, category: str, description: str = "") -> VariantGroup:
        """Get existing variant group or create a new one."""
        group = (
            self.session.query(VariantGroup)
            .filter_by(threat_category=category)
            .first()
        )
        if group:
            return group

        group = VariantGroup(
            id=str(uuid.uuid4()),
            threat_category=category,
            description=description or f"Variant twins for {category} defense",
        )
        self.session.add(group)
        self.session.commit()
        return group

    def _select_strategies(self, existing_strategies: list[str], count: int) -> list[dict]:
        """Select strategies not yet used in this group."""
        available = [s for s in _VARIANT_STRATEGIES if s["name"] not in existing_strategies]
        if len(available) < count:
            available = _VARIANT_STRATEGIES.copy()
        return available[:count]

    def generate_variants(
        self,
        category: str,
        defense_plan: dict,
        count: int | None = None,
    ) -> list[str]:
        """Generate variant twin implementations for a threat category.

        Uses Claude Code CLI to create each variant with a different
        detection strategy. Returns list of generated layer names.

        Args:
            category: Threat category (e.g. "prompt_injection")
            defense_plan: The defense plan dict from the classifier
            count: Number of variants to generate (default from config)

        Returns:
            List of successfully generated layer names.
        """
        count = count or self.variants_per_category
        group = self._get_or_create_group(category)

        # Check existing variants
        existing = (
            self.session.query(VariantMember)
            .filter_by(group_id=group.id)
            .all()
        )
        existing_strategies = [m.implementation_strategy for m in existing]
        needed = max(0, count - len(existing))

        if needed == 0:
            logger.info(
                "Sufficient variants exist",
                extra={"extra_data": {"category": category, "existing": len(existing)}},
            )
            return [m.layer_name for m in existing]

        strategies = self._select_strategies(existing_strategies, needed)
        generated: list[str] = []

        for strategy in strategies[:needed]:
            layer_name = f"variant_{category}_{strategy['name']}"
            safe_name = "".join(c if c.isalnum() or c == "_" else "_" for c in layer_name)
            class_name = "".join(word.capitalize() for word in safe_name.split("_"))
            output_file = str(self.output_dir / f"{safe_name}.py")

            prompt = _VARIANT_IMPLEMENTATION_PROMPT.format(
                category=category,
                strategy_name=strategy["name"],
                strategy_description=strategy["description"],
                strategy_instruction=strategy["instruction"],
                defense_plan=json.dumps(defense_plan, indent=2),
                output_file=output_file,
                class_name=class_name,
                layer_name=safe_name,
            )

            logger.info(
                "Generating variant",
                extra={"extra_data": {
                    "category": category,
                    "strategy": strategy["name"],
                    "file": output_file,
                }},
            )

            # Implement with retry
            result = self.claude_code.implement(prompt, output_file)
            if not result.get("success"):
                logger.warning(
                    "Variant generation failed",
                    extra={"extra_data": {
                        "strategy": strategy["name"],
                        "error": str(result.get("output", ""))[:300],
                    }},
                )
                continue

            verify = self.claude_code.verify_code(output_file)
            if not verify.get("success"):
                logger.warning(
                    "Variant verification failed",
                    extra={"extra_data": {"strategy": strategy["name"]}},
                )
                continue

            # Register variant member
            member = VariantMember(
                id=str(uuid.uuid4()),
                group_id=group.id,
                layer_name=safe_name,
                implementation_strategy=strategy["name"],
                file_path=output_file,
            )
            self.session.add(member)
            self.session.commit()
            generated.append(safe_name)

            logger.info(
                "Variant generated successfully",
                extra={"extra_data": {
                    "layer_name": safe_name,
                    "strategy": strategy["name"],
                }},
            )

        # Set initial active variant if none set
        if not group.active_variant and generated:
            group.active_variant = generated[0]
            self.session.commit()

        return generated

    def rotate_active_variant(self, category: str) -> str | None:
        """Rotate to the next variant for a threat category.

        Rotation strategy is per-group:
        - round_robin: Cycle through variants in order
        - best_performer: Switch to highest effectiveness score
        - random: Pick a random variant

        Returns the newly activated variant name, or None if rotation failed.
        """
        group = (
            self.session.query(VariantGroup)
            .filter_by(threat_category=category)
            .first()
        )
        if not group:
            return None

        members = (
            self.session.query(VariantMember)
            .filter_by(group_id=group.id)
            .all()
        )
        if len(members) < 2:
            return group.active_variant

        strategy = group.rotation_strategy or "round_robin"
        current = group.active_variant

        if strategy == "best_performer":
            best = max(members, key=lambda m: m.effectiveness_score)
            new_active = best.layer_name
        elif strategy == "random":
            candidates = [m for m in members if m.layer_name != current]
            new_active = random.choice(candidates).layer_name if candidates else current
        else:
            # round_robin
            names = [m.layer_name for m in members]
            try:
                idx = names.index(current)
                new_active = names[(idx + 1) % len(names)]
            except ValueError:
                new_active = names[0]

        # Update activation flags
        for m in members:
            m.is_active = (m.layer_name == new_active)
        group.active_variant = new_active
        self.session.commit()

        logger.info(
            "Variant rotated",
            extra={"extra_data": {
                "category": category,
                "from": current,
                "to": new_active,
                "strategy": strategy,
            }},
        )

        return new_active

    def regenerate_underperformer(
        self, category: str, min_effectiveness: float = 0.3
    ) -> list[str]:
        """Regenerate variant twins that are performing below threshold.

        Instead of just deactivating, uses Claude Code CLI to create a
        fresh implementation with the same strategy but improved logic.

        Returns list of regenerated layer names.
        """
        group = (
            self.session.query(VariantGroup)
            .filter_by(threat_category=category)
            .first()
        )
        if not group:
            return []

        members = (
            self.session.query(VariantMember)
            .filter_by(group_id=group.id)
            .all()
        )

        regenerated = []
        for member in members:
            if member.effectiveness_score >= min_effectiveness:
                continue

            logger.info(
                "Regenerating underperforming variant",
                extra={"extra_data": {
                    "layer_name": member.layer_name,
                    "current_score": member.effectiveness_score,
                }},
            )

            # Get strategy details
            strategy = next(
                (s for s in _VARIANT_STRATEGIES if s["name"] == member.implementation_strategy),
                _VARIANT_STRATEGIES[0],
            )

            prompt = (
                f"The previous implementation of '{member.layer_name}' at '{member.file_path}' "
                f"is underperforming (effectiveness: {member.effectiveness_score:.2f}). "
                f"Read the current file, understand why it's failing, and rewrite it with "
                f"significantly improved detection logic.\n\n"
                f"Strategy: {strategy['name']} — {strategy['instruction']}\n\n"
                f"Requirements:\n"
                f"- Keep the same class name and layer name\n"
                f"- Improve detection patterns and scoring\n"
                f"- Add edge cases the previous version missed\n"
                f"- Verify with: python3 -m py_compile {member.file_path}\n"
            )

            result = self.claude_code.implement(prompt, member.file_path)
            if result.get("success"):
                verify = self.claude_code.verify_code(member.file_path)
                if verify.get("success"):
                    member.effectiveness_score = 0.0  # Reset for fresh evaluation
                    self.session.commit()
                    regenerated.append(member.layer_name)

        return regenerated

    def get_variant_status(self) -> dict:
        """Return status of all variant groups and their members."""
        groups = self.session.query(VariantGroup).all()
        status = {}
        for group in groups:
            members = (
                self.session.query(VariantMember)
                .filter_by(group_id=group.id)
                .all()
            )
            status[group.threat_category] = {
                "active_variant": group.active_variant,
                "rotation_strategy": group.rotation_strategy,
                "variants": [
                    {
                        "name": m.layer_name,
                        "strategy": m.implementation_strategy,
                        "effectiveness": m.effectiveness_score,
                        "is_active": m.is_active,
                    }
                    for m in members
                ],
            }
        return status
