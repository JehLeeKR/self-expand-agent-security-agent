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
        """Build the prompt that Claude Code CLI will use to implement the layer."""
        layer_name = plan.get("layer_name", f"defense_{threat.category}_{threat.id[:8]}")
        output_file = str(self.output_dir / f"{layer_name}.py")

        prompt = (
            f"Implement a Python defense layer module at '{output_file}' for the "
            f"self-expand-agent-security-agent project.\n\n"
            f"## Threat Details\n"
            f"- Category: {threat.category}\n"
            f"- Severity: {threat.severity}\n"
            f"- Attack vector: {threat.attack_vector or 'N/A'}\n"
            f"- Affected components: {threat.affected_components or 'N/A'}\n\n"
            f"## Defense Plan\n{json.dumps(plan, indent=2)}\n\n"
            f"## Requirements\n"
            f"- Subclass `BaseDefenseLayer` from `src.defender.layers.base`.\n"
            f"- Set appropriate `name`, `priority`, and `threat_categories`.\n"
            f"- Implement `async inspect(self, data: DefenseContext) -> DefenseResult`.\n"
            f"- Implement `get_rules(self) -> list[DetectionRule]`.\n"
            f"- Use regex patterns and heuristic scoring.\n"
            f"- Return 'block' for high-confidence threats, 'flag' for medium, 'pass' for clean.\n"
            f"- Include proper error handling and logging via `src.utils.logging.get_logger()`.\n"
            f"- Production quality: type hints, docstrings, no placeholder code.\n"
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

        logger.info(
            "Implementing defense layer",
            extra={
                "extra_data": {
                    "threat_id": threat.id,
                    "category": threat.category,
                    "output_file": output_file,
                }
            },
        )

        # Step 1: Generate code via Claude Code CLI.
        result = self.claude_code.implement(prompt, output_file)
        if not result.get("success"):
            logger.error(
                "Code generation failed",
                extra={
                    "extra_data": {
                        "threat_id": threat.id,
                        "output": str(result.get("output", ""))[:500],
                    }
                },
            )
            return False

        # Step 2: Verify generated code.
        verify = self.claude_code.verify_code(output_file)
        if not verify.get("success"):
            logger.error(
                "Code verification failed",
                extra={
                    "extra_data": {
                        "threat_id": threat.id,
                        "output": str(verify.get("output", ""))[:500],
                    }
                },
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
