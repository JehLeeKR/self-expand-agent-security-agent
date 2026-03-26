"""AI-powered defense planning that generates implementation strategies for threats."""

import json

from src.db.models import ClassifiedThreat
from src.db.result_store import ResultStore
from src.db.threat_store import ThreatStore
from src.utils.claude_api import ClaudeAPI
from src.utils.logging import get_logger

logger = get_logger()

PLANNER_SYSTEM_PROMPT = """\
You are a senior AI security engineer designing defense layers for an LLM-based \
agent system. Given a classified threat, you must produce a concrete implementation \
plan for a defense layer that can detect and prevent the described attack.

## Architecture context
The agent system processes requests through an ordered pipeline of defense layers. \
Each layer is a Python module that implements `detect(request) -> DetectionResult` \
and optionally `prevent(request) -> PreventionResult`. Layers are executed by \
priority (lower number = earlier in pipeline). A layer can inspect and transform \
the input, the model's output, tool calls, or context window contents.

## Currently active defense layers
{active_layers}

## Your task
Analyze the classified threat below and produce an implementation plan. If an \
existing layer already partially covers this threat, recommend updating it rather \
than creating a new one. If the threat is novel, design a new layer.

## Output format
Return a single JSON object with these exact keys:
{{
  "layer_name": "<snake_case name for the defense layer>",
  "layer_type": "<new|update>",
  "detection_rules": [
    {{
      "rule_id": "<unique snake_case identifier>",
      "description": "<what this rule detects>",
      "pattern_type": "<regex|semantic|heuristic|statistical>",
      "pattern": "<the detection pattern, regex string, or heuristic description>",
      "target": "<input|output|context|tools|storage>",
      "confidence_threshold": <float 0.0-1.0>
    }}
  ],
  "pseudocode": "<multi-line Python-style pseudocode for the core detection and \
prevention logic, written as a single string with newline characters>",
  "integration_points": [
    "<where in the agent pipeline this layer hooks in, e.g. 'pre_model_call', \
'post_model_call', 'pre_tool_execution', 'context_assembly'>"
  ],
  "priority": <integer, lower = earlier in pipeline; suggest relative to existing layers>
}}

Be specific in detection_rules — provide actual regex patterns where applicable, \
describe semantic checks with enough detail to implement them, and set realistic \
confidence thresholds. The pseudocode should be implementable by another engineer \
without additional context.
"""


class DefensePlanner:
    """Generates defense implementation plans for classified threats using Claude."""

    def __init__(
        self,
        claude_api: ClaudeAPI,
        threat_store: ThreatStore,
        result_store: ResultStore,
    ):
        self.claude_api = claude_api
        self.threat_store = threat_store
        self.result_store = result_store

    def _build_system_prompt(self) -> str:
        """Build the system prompt with current active defense layers."""
        active_layers = self.result_store.get_active_layers()
        if not active_layers:
            layers_description = "(No defense layers are currently active.)"
        else:
            layer_entries = []
            for layer in active_layers:
                categories = layer.get_threat_categories()
                rules_raw = layer.detection_rules
                rules = json.loads(rules_raw) if rules_raw else []
                rule_summaries = [
                    r.get("description", r.get("rule_id", "unknown"))
                    for r in rules
                ]
                layer_entries.append(
                    f"- {layer.name} (priority {layer.priority}, "
                    f"module: {layer.module_path}): "
                    f"covers {categories}, "
                    f"effectiveness {layer.effectiveness_score:.0%}, "
                    f"rules: {rule_summaries}"
                )
            layers_description = "\n".join(layer_entries)

        return PLANNER_SYSTEM_PROMPT.format(active_layers=layers_description)

    def _build_user_message(self, threat: ClassifiedThreat) -> str:
        """Format the classified threat as a user message for Claude."""
        affected = threat.get_affected_components()
        covered = threat.get_covered_by_layers()
        return (
            f"## Classified Threat\n"
            f"**ID:** {threat.id}\n"
            f"**Category:** {threat.category}\n"
            f"**Severity:** {threat.severity}\n"
            f"**Attack vector:** {threat.attack_vector}\n"
            f"**Affected components:** {affected}\n"
            f"**Currently covered by layers:** {covered}\n\n"
            f"Design a defense layer (or update to an existing one) that will "
            f"detect and prevent this attack."
        )

    def plan_defense(self, threat: ClassifiedThreat) -> dict:
        """Generate a defense implementation plan for a classified threat.

        Args:
            threat: The classified threat to plan defenses for.

        Returns:
            A dict containing the defense plan with layer_name, layer_type,
            detection_rules, pseudocode, integration_points, and priority.

        Raises:
            ValueError: If Claude returns unparseable or invalid JSON.
        """
        system_prompt = self._build_system_prompt()
        user_message = self._build_user_message(threat)

        try:
            result = self.claude_api.query_json(system_prompt, user_message)
        except (json.JSONDecodeError, Exception) as exc:
            logger.error(
                "Failed to parse defense plan response from Claude",
                extra={"extra_data": {"threat_id": threat.id, "error": str(exc)}},
            )
            raise ValueError(
                f"Claude returned invalid JSON for threat {threat.id}: {exc}"
            ) from exc

        # Validate required keys
        required_keys = {
            "layer_name", "layer_type", "detection_rules",
            "pseudocode", "integration_points", "priority",
        }
        missing = required_keys - set(result.keys())
        if missing:
            logger.warning(
                "Defense plan missing keys, filling defaults",
                extra={"extra_data": {"missing": list(missing), "threat_id": threat.id}},
            )
            result.setdefault("layer_name", f"defense_{threat.category}")
            result.setdefault("layer_type", "new")
            result.setdefault("detection_rules", [])
            result.setdefault("pseudocode", "# No pseudocode generated")
            result.setdefault("integration_points", ["pre_model_call"])
            result.setdefault("priority", 50)

        # Normalise layer_type
        if result["layer_type"] not in ("new", "update"):
            result["layer_type"] = "new"

        # Ensure priority is an integer
        try:
            result["priority"] = int(result["priority"])
        except (TypeError, ValueError):
            result["priority"] = 50

        # Ensure detection_rules is a list
        if not isinstance(result["detection_rules"], list):
            result["detection_rules"] = []

        # Ensure integration_points is a list
        if not isinstance(result["integration_points"], list):
            result["integration_points"] = [str(result["integration_points"])]

        logger.info(
            "Defense plan generated",
            extra={"extra_data": {
                "threat_id": threat.id,
                "layer_name": result["layer_name"],
                "layer_type": result["layer_type"],
                "rule_count": len(result["detection_rules"]),
            }},
        )
        return result

    def run(self) -> int:
        """Generate defense plans for all newly classified threats.

        Processes threats with status='new', generates a plan for each,
        stores the plan in the threat record, and updates status to 'planned'.

        Returns:
            Number of threats successfully planned.
        """
        new_threats = self.threat_store.get_threats_by_status("new")
        if not new_threats:
            logger.info("No new threats to plan defenses for")
            return 0

        logger.info(
            "Starting defense planning run",
            extra={"extra_data": {"count": len(new_threats)}},
        )

        planned_count = 0
        for threat in new_threats:
            try:
                plan = self.plan_defense(threat)

                # Store the plan in the threat record
                threat.defense_plan = json.dumps(plan)
                self.threat_store.update_threat_status(threat.id, "planned")
                planned_count += 1
            except (ValueError, Exception) as exc:
                logger.error(
                    "Failed to plan defense for threat, skipping",
                    extra={"extra_data": {
                        "threat_id": threat.id,
                        "category": threat.category,
                        "error": str(exc),
                    }},
                )

        logger.info(
            "Defense planning run complete",
            extra={"extra_data": {
                "total": len(new_threats),
                "planned": planned_count,
                "failed": len(new_threats) - planned_count,
            }},
        )
        return planned_count
