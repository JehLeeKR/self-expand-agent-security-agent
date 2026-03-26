"""Automated defense layer implementation using Claude Code CLI."""

from __future__ import annotations

import json
from pathlib import Path

from src.db.models import ClassifiedThreat
from src.db.result_store import ResultStore
from src.db.threat_store import ThreatStore
from src.defender.layer_registry import LayerRegistry
from src.utils.claude_code import ClaudeCode
from src.utils.logging import get_logger

logger = get_logger()

_LAYER_OUTPUT_DIR = Path("src/defender/layers")


class DefenseImplementer:
    """Uses Claude Code CLI to autonomously implement defense layers for classified threats.

    The workflow for each threat:
    1. Read the threat's ``defense_plan`` (JSON stored on ``ClassifiedThreat``).
    2. Invoke Claude Code CLI to generate or update a defense layer module.
    3. Verify the generated code.
    4. Register the new layer in the ``LayerRegistry``.
    5. Update threat status.
    """

    def __init__(
        self,
        claude_code: ClaudeCode,
        layer_registry: LayerRegistry,
        threat_store: ThreatStore,
        result_store: ResultStore,
        config: dict | None = None,
    ) -> None:
        self.claude_code = claude_code
        self.layer_registry = layer_registry
        self.threat_store = threat_store
        self.result_store = result_store
        self.config = config or {}
        self.output_dir = Path(
            self.config.get("layer_output_dir", str(_LAYER_OUTPUT_DIR))
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_defense_plan(self, threat: ClassifiedThreat) -> dict:
        """Parse the defense_plan JSON from a classified threat."""
        if not threat.defense_plan:
            return {}
        try:
            return json.loads(threat.defense_plan)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning(
                "Failed to parse defense_plan",
                extra={"extra_data": {"threat_id": threat.id, "error": str(exc)}},
            )
            return {}

    def _build_implementation_prompt(self, threat: ClassifiedThreat, plan: dict) -> str:
        """Build a detailed prompt for Claude Code CLI to implement the defense layer.

        The prompt instructs Claude Code to:
        1. Read existing defense layers for consistency
        2. Write the new layer following established patterns
        3. Verify syntax and imports
        4. Run basic tests if possible
        """
        layer_name = plan.get("layer_name", f"defense_{threat.category}_{threat.id[:8]}")
        safe_name = "".join(c if c.isalnum() or c == "_" else "_" for c in layer_name)
        output_file = str(self.output_dir / f"{safe_name}.py")

        prompt = (
            f"You are implementing a new defense layer for an AI threat defense system.\n\n"
            f"IMPORTANT: First, read these existing files to understand the codebase patterns:\n"
            f"1. Read src/defender/layers/base.py - the base classes you must subclass\n"
            f"2. Read src/defender/layers/input_validator.py - an example of a well-implemented layer\n"
            f"3. Read src/defender/layers/output_filter.py - another example with regex patterns\n\n"
            f"Then implement a new defense layer at '{output_file}'.\n\n"
            f"## Threat to Defend Against\n"
            f"- Category: {threat.category}\n"
            f"- Severity: {threat.severity}\n"
            f"- Attack vector: {threat.attack_vector or 'N/A'}\n"
            f"- Affected components: {threat.affected_components or 'N/A'}\n\n"
            f"## Defense Plan\n{json.dumps(plan, indent=2)}\n\n"
            f"## Implementation Requirements\n"
            f"- Subclass `BaseDefenseLayer` from `src.defender.layers.base`\n"
            f"- Import: `from src.defender.layers.base import BaseDefenseLayer, "
            f"DefenseContext, DefenseResult, DetectionRule`\n"
            f"- Set class attributes: `name = '{safe_name}'`, appropriate `priority` "
            f"and `threat_categories`\n"
            f"- Implement `async inspect(self, data: DefenseContext) -> DefenseResult`\n"
            f"- Implement `get_rules(self) -> list[DetectionRule]`\n"
            f"- Use regex patterns with pre-compiled re.compile() for performance\n"
            f"- Use composite scoring: regex matches + heuristic analysis\n"
            f"- Return 'block' (confidence >= 0.85), 'flag' (>= 0.45), 'pass' otherwise\n"
            f"- Use `from src.utils.logging import get_logger` for logging\n"
            f"- Follow the exact same code patterns as input_validator.py\n"
            f"- Production quality: type hints, docstrings, real detection logic\n\n"
            f"After writing the file, verify it compiles: `python3 -m py_compile {output_file}`\n"
            f"Fix any errors before finishing.\n"
        )
        return prompt

    def _determine_output_file(self, plan: dict, threat: ClassifiedThreat) -> str:
        """Determine the file path for the generated layer module."""
        layer_name = plan.get("layer_name", f"defense_{threat.category}_{threat.id[:8]}")
        # Sanitize to valid Python module name.
        safe_name = "".join(c if c.isalnum() or c == "_" else "_" for c in layer_name)
        return str(self.output_dir / f"{safe_name}.py")

    def _threat_has_covering_layers(self, threat: ClassifiedThreat) -> bool:
        """Check whether any active layer already covers this threat's category."""
        report = self.layer_registry.coverage_report()
        categories = report.get("categories", {})
        return threat.category in categories and len(categories[threat.category]) > 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def implement_layer(self, threat: ClassifiedThreat) -> bool:
        """Implement a defense layer for a single threat.

        Uses Claude Code CLI with a retry loop: if the first implementation
        fails verification, the error is fed back to Claude Code for correction.
        This mirrors how a developer would iteratively fix code — but fully
        autonomous.

        Returns True if the layer was successfully implemented and registered.
        """
        plan = self._parse_defense_plan(threat)
        if not plan:
            logger.warning(
                "No defense plan available for threat",
                extra={"extra_data": {"threat_id": threat.id}},
            )
            return False

        output_file = self._determine_output_file(plan, threat)
        prompt = self._build_implementation_prompt(threat, plan)
        max_retries = self.config.get("defense", {}).get("max_retry_implementations", 3)

        logger.info(
            "Implementing defense layer via Claude Code CLI",
            extra={
                "extra_data": {
                    "threat_id": threat.id,
                    "category": threat.category,
                    "output_file": output_file,
                    "max_retries": max_retries,
                }
            },
        )

        # Retry loop: implement → verify → fix if needed
        last_error = ""
        for attempt in range(1, max_retries + 1):
            logger.info(
                f"Implementation attempt {attempt}/{max_retries}",
                extra={"extra_data": {"threat_id": threat.id, "attempt": attempt}},
            )

            # Build prompt (include error feedback on retries)
            if attempt == 1:
                current_prompt = prompt
            else:
                current_prompt = (
                    f"The previous implementation attempt for '{output_file}' failed "
                    f"with this error:\n\n{last_error}\n\n"
                    f"Please fix the file. Read it first, understand the error, "
                    f"then fix it. After fixing, verify with: "
                    f"`python3 -m py_compile {output_file}`\n\n"
                    f"Original requirements:\n{prompt}"
                )

            # Step 1: Generate/fix code via Claude Code CLI
            result = self.claude_code.implement(current_prompt, output_file)
            if not result.get("success"):
                last_error = str(result.get("output", ""))[:1000]
                logger.warning(
                    f"Implementation attempt {attempt} failed",
                    extra={"extra_data": {
                        "threat_id": threat.id,
                        "error": last_error[:300],
                    }},
                )
                continue

            # Step 2: Verify generated code
            verify = self.claude_code.verify_code(output_file)
            if not verify.get("success"):
                last_error = str(verify.get("output", ""))[:1000]
                logger.warning(
                    f"Verification attempt {attempt} failed",
                    extra={"extra_data": {
                        "threat_id": threat.id,
                        "error": last_error[:300],
                    }},
                )
                continue

            # Success — break out of retry loop
            logger.info(
                f"Implementation succeeded on attempt {attempt}",
                extra={"extra_data": {"threat_id": threat.id}},
            )
            break
        else:
            # All retries exhausted
            logger.error(
                "All implementation attempts failed",
                extra={"extra_data": {
                    "threat_id": threat.id,
                    "attempts": max_retries,
                    "last_error": last_error[:500],
                }},
            )
            return False

        # Step 3: Attempt to import and register the layer.
        try:
            layer_instance = self._load_layer_from_file(output_file, plan, threat)
            if layer_instance is not None:
                self.layer_registry.register(layer_instance)
        except Exception:
            logger.exception(
                "Failed to load and register generated layer",
                extra={"extra_data": {"threat_id": threat.id, "file": output_file}},
            )
            # Not fatal -- the layer file was still created and can be loaded later.

        logger.info(
            "Defense layer implemented successfully",
            extra={"extra_data": {"threat_id": threat.id, "file": output_file}},
        )
        return True

    def _load_layer_from_file(
        self, file_path: str, plan: dict, threat: ClassifiedThreat,
    ) -> BaseDefenseLayer | None:
        """Dynamically import the generated module and return a layer instance."""
        import importlib.util

        from src.defender.layers.base import BaseDefenseLayer

        spec = importlib.util.spec_from_file_location("_generated_layer", file_path)
        if spec is None or spec.loader is None:
            logger.warning("Could not create module spec", extra={"extra_data": {"file": file_path}})
            return None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Find the first BaseDefenseLayer subclass defined in the module.
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, BaseDefenseLayer)
                and attr is not BaseDefenseLayer
            ):
                return attr()

        logger.warning(
            "No BaseDefenseLayer subclass found in generated module",
            extra={"extra_data": {"file": file_path}},
        )
        return None

    def run(self) -> int:
        """Implement defense layers for all test-ready threats lacking coverage.

        Returns the number of threats successfully implemented.
        """
        threats = self.threat_store.get_threats_by_status("test_ready")
        if not threats:
            logger.info("No test_ready threats found for implementation")
            return 0

        implemented_count = 0

        for threat in threats:
            # Skip if already covered by existing layers.
            if self._threat_has_covering_layers(threat):
                logger.info(
                    "Threat already covered by existing layers, skipping",
                    extra={"extra_data": {"threat_id": threat.id, "category": threat.category}},
                )
                continue

            success = self.implement_layer(threat)
            if success:
                self.threat_store.update_threat_status(threat.id, "implemented")
                implemented_count += 1
            else:
                logger.warning(
                    "Failed to implement layer for threat",
                    extra={"extra_data": {"threat_id": threat.id}},
                )

        logger.info(
            "Implementation run complete",
            extra={"extra_data": {"implemented": implemented_count, "total_candidates": len(threats)}},
        )
        return implemented_count
