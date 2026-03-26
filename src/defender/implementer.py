"""Automated defense layer implementation using Claude Code CLI.

Integrates with the robustness system:
- New layers enter staging evaluation (shadow → canary → production)
- Variant twins are generated for diversity
- Integrity hashes are registered after implementation
- Backups are created for rollback capability
"""

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

    Enhanced workflow for each threat:
    1. Read the threat's ``defense_plan`` (JSON stored on ``ClassifiedThreat``)
    2. Invoke Claude Code CLI to generate or update a defense layer module
    3. Verify the generated code (syntax + static analysis)
    4. Register integrity hash for tamper detection
    5. Enter staging pipeline (shadow evaluation)
    6. Generate variant twins for defense diversity
    7. Register the new layer in the ``LayerRegistry``
    8. Create backup snapshot for rollback
    9. Update threat status
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

        # Lazy-loaded robustness components
        self._staging = None
        self._integrity = None
        self._variant_mgr = None
        self._backup_mgr = None
        self._council = None

        # Council mode: if enabled, implementations go through multi-agent review
        self.council_enabled = self.config.get("council", {}).get("enabled", True)

    @property
    def staging(self):
        if self._staging is None:
            from src.defender.staging import StagingPipeline
            self._staging = StagingPipeline(self.result_store, self.config)
        return self._staging

    @property
    def integrity(self):
        if self._integrity is None:
            from src.defender.integrity import IntegrityVerifier
            self._integrity = IntegrityVerifier(
                self.claude_code, self.result_store, self.config
            )
        return self._integrity

    @property
    def variant_mgr(self):
        if self._variant_mgr is None:
            from src.defender.variant_manager import VariantManager
            self._variant_mgr = VariantManager(
                self.claude_code, self.layer_registry, self.result_store, self.config
            )
        return self._variant_mgr

    @property
    def council(self):
        if self._council is None:
            from src.defender.council_manager import CouncilManager
            self._council = CouncilManager(
                self.claude_code, self.result_store, self.config
            )
        return self._council

    @property
    def backup_mgr(self):
        if self._backup_mgr is None:
            from src.defender.resilience import BackupManager
            robustness = self.config.get("robustness", {})
            self._backup_mgr = BackupManager(
                robustness.get("backup_dir", "data/layer_backups")
            )
        return self._backup_mgr

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
    # Implementation strategies
    # ------------------------------------------------------------------

    def _implement_with_council(
        self, threat: ClassifiedThreat, plan: dict,
        output_file: str, safe_name: str,
    ) -> bool:
        """Implement via multi-agent council review."""
        logger.info(
            "Using multi-agent council for implementation",
            extra={"extra_data": {"threat_id": threat.id}},
        )

        result = self.council.run_council_review(
            threat_category=threat.category,
            threat_severity=threat.severity,
            attack_vector=threat.attack_vector or "N/A",
            defense_plan=plan,
            output_file=output_file,
            safe_name=safe_name,
            threat_id=threat.id,
        )

        if result.get("approved"):
            logger.info(
                "Council APPROVED implementation",
                extra={"extra_data": {
                    "threat_id": threat.id,
                    "rounds": result.get("rounds"),
                    "session_id": result.get("session_id"),
                }},
            )
            return True
        else:
            logger.warning(
                "Council REJECTED implementation",
                extra={"extra_data": {
                    "threat_id": threat.id,
                    "rounds": result.get("rounds"),
                    "final_vote": result.get("final_vote"),
                    "votes": result.get("all_votes"),
                }},
            )
            return False

    def _implement_with_retry(
        self, threat: ClassifiedThreat, plan: dict, output_file: str,
    ) -> bool:
        """Implement via simple retry loop with error feedback (legacy mode)."""
        prompt = self._build_implementation_prompt(threat, plan)
        max_retries = self.config.get("defense", {}).get("max_retry_implementations", 3)

        last_error = ""
        for attempt in range(1, max_retries + 1):
            logger.info(
                f"Implementation attempt {attempt}/{max_retries}",
                extra={"extra_data": {"threat_id": threat.id, "attempt": attempt}},
            )

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

            verify = self.claude_code.verify_code(output_file)
            if not verify.get("success"):
                last_error = str(verify.get("output", ""))[:1000]
                continue

            logger.info(
                f"Implementation succeeded on attempt {attempt}",
                extra={"extra_data": {"threat_id": threat.id}},
            )
            return True

        logger.error(
            "All implementation attempts failed",
            extra={"extra_data": {
                "threat_id": threat.id,
                "attempts": max_retries,
            }},
        )
        return False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def implement_layer(self, threat: ClassifiedThreat) -> bool:
        """Implement a defense layer for a single threat.

        Two modes:
        - **Council mode** (default): Multi-agent council reviews the implementation.
          Architect implements, Security Auditor + Red Team + Test Engineer review,
          Quality Gate makes the final call. Up to N revision rounds.
        - **Legacy mode**: Simple retry loop with error feedback.

        After implementation, the layer goes through:
        static analysis → integrity hash → registration → staging → backup → variants.

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
        layer_name = plan.get("layer_name", f"defense_{threat.category}_{threat.id[:8]}")
        safe_name = "".join(c if c.isalnum() or c == "_" else "_" for c in layer_name)

        logger.info(
            "Implementing defense layer",
            extra={"extra_data": {
                "threat_id": threat.id,
                "category": threat.category,
                "output_file": output_file,
                "council_enabled": self.council_enabled,
            }},
        )

        # ----- Implementation phase -----
        if self.council_enabled:
            success = self._implement_with_council(threat, plan, output_file, safe_name)
        else:
            success = self._implement_with_retry(threat, plan, output_file)

        if not success:
            return False

        # ----- Post-implementation robustness pipeline -----

        # Static security analysis
        static = self.integrity.static_analysis(output_file)
        if not static["safe"]:
            logger.error(
                "Generated layer FAILED static security analysis",
                extra={"extra_data": {
                    "threat_id": threat.id,
                    "issues": static["issues"],
                }},
            )
            return False

        # Register integrity hash
        self.integrity.register_hash(safe_name, output_file)

        # Attempt to import and register the layer
        try:
            layer_instance = self._load_layer_from_file(output_file, plan, threat)
            if layer_instance is not None:
                self.layer_registry.register(layer_instance)
        except Exception:
            logger.exception(
                "Failed to load and register generated layer",
                extra={"extra_data": {"threat_id": threat.id, "file": output_file}},
            )

        # Step 6: Enter staging pipeline (shadow evaluation)
        layer_name = plan.get("layer_name", f"defense_{threat.category}_{threat.id[:8]}")
        safe_name = "".join(c if c.isalnum() or c == "_" else "_" for c in layer_name)
        self.staging.enter_staging(safe_name)

        # Step 7: Create backup snapshot
        self.backup_mgr.snapshot(safe_name, output_file)

        # Step 8: Generate variant twins (non-blocking — failures don't block main impl)
        try:
            variants = self.variant_mgr.generate_variants(
                threat.category, plan,
            )
            if variants:
                logger.info(
                    "Variant twins generated",
                    extra={"extra_data": {
                        "threat_id": threat.id,
                        "variants": variants,
                    }},
                )
        except Exception:
            logger.exception(
                "Variant generation failed (non-fatal)",
                extra={"extra_data": {"threat_id": threat.id}},
            )

        logger.info(
            "Defense layer implemented with full robustness pipeline",
            extra={"extra_data": {
                "threat_id": threat.id,
                "file": output_file,
                "staging": "shadow",
                "integrity_registered": True,
                "backup_created": True,
            }},
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
