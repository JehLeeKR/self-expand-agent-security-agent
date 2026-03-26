"""Registry and pipeline orchestrator for defense layers."""

from __future__ import annotations

import asyncio
from collections import defaultdict

from src.db.result_store import ResultStore
from src.defender.layers.base import (
    BaseDefenseLayer,
    DefenseContext,
    DefenseResult,
)
from src.utils.logging import get_logger

logger = get_logger()


class LayerRegistry:
    """Central registry that manages defense layer lifecycle and pipeline execution.

    Layers are kept in memory for fast access and mirrored to the database
    via ``ResultStore`` for persistence and effectiveness tracking.
    """

    def __init__(self, result_store: ResultStore) -> None:
        self.result_store = result_store
        self._layers: dict[str, BaseDefenseLayer] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, layer: BaseDefenseLayer) -> None:
        """Register a defense layer in memory and persist to DB."""
        name = layer.name
        self._layers[name] = layer

        rules = layer.get_rules()
        rule_dicts = [
            {"name": r.name, "pattern": r.pattern, "description": r.description, "severity": r.severity}
            for r in rules
        ]

        module_path = f"{type(layer).__module__}.{type(layer).__qualname__}"

        self.result_store.register_layer(
            name=name,
            module_path=module_path,
            priority=layer.priority,
            threat_categories=layer.threat_categories,
            detection_rules=rule_dicts,
        )
        logger.info(
            "Registered defense layer",
            extra={"extra_data": {"layer": name, "priority": layer.priority}},
        )

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------

    def get_pipeline(self) -> list[BaseDefenseLayer]:
        """Return all registered layers sorted by priority (ascending)."""
        return sorted(self._layers.values(), key=lambda l: l.priority)

    async def run_pipeline(self, context: DefenseContext) -> list[DefenseResult]:
        """Run all active layers in priority order.

        Stops early on the first ``block`` result -- subsequent layers are
        not executed.  ``flag`` results are accumulated but do not halt
        processing.

        Returns:
            List of ``DefenseResult`` objects, one per executed layer.
        """
        results: list[DefenseResult] = []

        # Fetch active layer names from DB to respect runtime activation state.
        active_db_layers = {l.name for l in self.result_store.get_active_layers()}

        for layer in self.get_pipeline():
            if layer.name not in active_db_layers:
                continue

            try:
                result = await layer.inspect(context)
            except Exception:
                logger.exception(
                    "Defense layer raised an exception",
                    extra={"extra_data": {"layer": layer.name}},
                )
                # Treat layer errors as a pass so we don't block legitimate traffic
                # due to a buggy layer, but flag for investigation.
                result = DefenseResult(
                    action="flag",
                    reason=f"Layer '{layer.name}' raised an exception during inspection",
                    confidence=0.0,
                )

            results.append(result)

            if result.action == "block":
                logger.info(
                    "Pipeline halted by block",
                    extra={
                        "extra_data": {
                            "blocking_layer": layer.name,
                            "reason": result.reason,
                        }
                    },
                )
                break

        return results

    # ------------------------------------------------------------------
    # Built-in layer loading
    # ------------------------------------------------------------------

    def load_builtin_layers(self) -> None:
        """Instantiate and register all built-in defense layers."""
        from src.defender.layers.context_isolator import ContextIsolator
        from src.defender.layers.input_validator import InputValidator
        from src.defender.layers.output_filter import OutputFilter
        from src.defender.layers.rate_limiter import RateLimiter
        from src.defender.layers.tool_sandbox import ToolSandbox

        builtin: list[BaseDefenseLayer] = [
            InputValidator(),
            ContextIsolator(),
            ToolSandbox(),
            RateLimiter(),
            OutputFilter(),
        ]

        for layer in builtin:
            if layer.name not in self._layers:
                self.register(layer)

        logger.info(
            "Built-in layers loaded",
            extra={"extra_data": {"count": len(builtin)}},
        )

    # ------------------------------------------------------------------
    # Coverage analysis
    # ------------------------------------------------------------------

    def coverage_report(self) -> dict:
        """Analyse threat category coverage across all registered layers.

        Returns a dict with:
            - ``categories``: mapping of category -> list of covering layer names
            - ``total_layers``: count of registered layers
            - ``total_categories``: count of unique categories covered
            - ``uncovered``: list of well-known categories with no covering layer
        """
        well_known_categories = {
            "prompt_injection",
            "jailbreak",
            "context_manipulation",
            "tool_abuse",
            "data_exfiltration",
            "privilege_escalation",
        }

        category_map: dict[str, list[str]] = defaultdict(list)
        for layer in self._layers.values():
            for cat in layer.threat_categories:
                category_map[cat].append(layer.name)

        covered = set(category_map.keys())
        uncovered = sorted(well_known_categories - covered)

        return {
            "categories": dict(category_map),
            "total_layers": len(self._layers),
            "total_categories": len(covered),
            "uncovered": uncovered,
        }
