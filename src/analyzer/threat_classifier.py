"""AI-powered threat classification using Claude for semantic analysis."""

import json

from src.db.models import ClassifiedThreat, RawThreat
from src.db.result_store import ResultStore
from src.db.threat_store import ThreatStore
from src.utils.claude_api import ClaudeAPI
from src.utils.logging import get_logger

logger = get_logger()

CLASSIFIER_SYSTEM_PROMPT = """\
You are an expert AI security analyst specializing in threats against LLM-based \
agent systems. Your task is to classify a newly discovered threat report into a \
structured taxonomy used by an automated defense pipeline.

## Threat categories (pick exactly one)
- prompt_injection: Attacks that manipulate the model's instructions via crafted \
  user input, including direct injection, indirect injection through retrieved \
  documents, and instruction-hierarchy attacks.
- data_exfiltration: Techniques that cause the agent to leak sensitive data from \
  its context, system prompt, tool outputs, or connected data stores to an \
  unauthorized party.
- jailbreak: Methods that bypass the model's safety alignment or content policy, \
  including DAN-style role-play, multi-turn escalation, encoding tricks, and \
  language-switching attacks.
- tool_abuse: Attacks that trick the agent into misusing its available tools \
  (API calls, code execution, file access, web browsing) to perform unintended \
  or harmful actions.
- context_manipulation: Techniques that corrupt, poison, or overflow the agent's \
  context window to degrade performance, inject hidden instructions, or cause \
  the agent to ignore prior constraints.
- privilege_escalation: Attacks where the agent is manipulated into accessing \
  resources, performing operations, or assuming roles beyond its authorized scope.

## Severity levels
- critical: Actively exploited or trivially exploitable with severe impact \
  (full system compromise, unrestricted data access).
- high: Reliably exploitable with significant impact (partial data leak, \
  meaningful safety bypass).
- medium: Exploitable under specific conditions or with moderate impact.
- low: Theoretical, requires unlikely preconditions, or has minimal impact.

## Affected components (select all that apply)
- input: The user-facing input channel or prompt interface.
- output: The model's response stream or rendered output.
- context: The conversation history, system prompt, or retrieval-augmented \
  context window.
- tools: Any external tool, function call, or plugin the agent can invoke.
- storage: Persistent data stores, vector databases, or file systems the agent \
  accesses.

## Existing defense layers
The following defense layers are currently active. Evaluate whether any of them \
would already detect or mitigate the described threat. List matching layer names \
in `covered_by_layers`. If none match, return an empty list.

{active_layers}

## Output format
Return a single JSON object with these exact keys:
{{
  "category": "<one of the six categories>",
  "severity": "<critical|high|medium|low>",
  "attack_vector": "<concise one-paragraph description of how the attack works>",
  "affected_components": ["<component>", ...],
  "covered_by_layers": ["<layer_name>", ...]
}}
"""


class ThreatClassifier:
    """Classifies raw threat intelligence into structured categories using Claude."""

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
                layer_entries.append(
                    f"- {layer.name} (priority {layer.priority}): "
                    f"covers {categories}, "
                    f"effectiveness {layer.effectiveness_score:.0%}, "
                    f"{len(rules)} detection rule(s)"
                )
            layers_description = "\n".join(layer_entries)

        return CLASSIFIER_SYSTEM_PROMPT.format(active_layers=layers_description)

    def _build_user_message(self, raw_threat: RawThreat) -> str:
        """Format the raw threat as a user message for Claude."""
        content = raw_threat.raw_content or raw_threat.summary or ""
        return (
            f"## Threat Report\n"
            f"**Title:** {raw_threat.title}\n"
            f"**Source:** {raw_threat.source}\n"
            f"**URL:** {raw_threat.source_url or 'N/A'}\n\n"
            f"**Summary:** {raw_threat.summary or 'N/A'}\n\n"
            f"**Full content:**\n{content}\n\n"
            f"Classify this threat according to the taxonomy above."
        )

    def classify_threat(self, raw_threat: RawThreat) -> ClassifiedThreat:
        """Classify a single raw threat using Claude and store the result.

        Args:
            raw_threat: The unclassified threat to analyze.

        Returns:
            The newly created ClassifiedThreat record.

        Raises:
            ValueError: If Claude returns unparseable or invalid JSON.
        """
        valid_categories = {
            "prompt_injection", "data_exfiltration", "jailbreak",
            "tool_abuse", "context_manipulation", "privilege_escalation",
        }
        valid_severities = {"critical", "high", "medium", "low"}
        valid_components = {"input", "output", "context", "tools", "storage"}

        system_prompt = self._build_system_prompt()
        user_message = self._build_user_message(raw_threat)

        try:
            result = self.claude_api.query_json(system_prompt, user_message)
        except (json.JSONDecodeError, Exception) as exc:
            logger.error(
                "Failed to parse classification response from Claude",
                extra={"extra_data": {"threat_id": raw_threat.id, "error": str(exc)}},
            )
            raise ValueError(
                f"Claude returned invalid JSON for threat {raw_threat.id}: {exc}"
            ) from exc

        # Validate and sanitise fields
        category = result.get("category", "")
        if category not in valid_categories:
            logger.warning(
                "Invalid category from Claude, defaulting to prompt_injection",
                extra={"extra_data": {"raw_category": category}},
            )
            category = "prompt_injection"

        severity = result.get("severity", "")
        if severity not in valid_severities:
            logger.warning(
                "Invalid severity from Claude, defaulting to medium",
                extra={"extra_data": {"raw_severity": severity}},
            )
            severity = "medium"

        affected_components = [
            c for c in result.get("affected_components", [])
            if c in valid_components
        ]
        if not affected_components:
            affected_components = ["input"]

        covered_by_layers = result.get("covered_by_layers", [])
        if not isinstance(covered_by_layers, list):
            covered_by_layers = []

        attack_vector = result.get("attack_vector", "No attack vector description provided.")

        classified = self.threat_store.add_classified_threat(
            raw_threat_id=raw_threat.id,
            category=category,
            severity=severity,
            attack_vector=attack_vector,
            affected_components=json.dumps(affected_components),
            covered_by_layers=json.dumps(covered_by_layers),
            status="new",
        )

        logger.info(
            "Threat classified",
            extra={"extra_data": {
                "threat_id": classified.id,
                "raw_threat_id": raw_threat.id,
                "category": category,
                "severity": severity,
            }},
        )
        return classified

    def run(self) -> int:
        """Classify all unclassified threats.

        Returns:
            Number of threats successfully classified.
        """
        raw_threats = self.threat_store.get_unclassified_threats()
        if not raw_threats:
            logger.info("No unclassified threats found")
            return 0

        logger.info(
            "Starting classification run",
            extra={"extra_data": {"count": len(raw_threats)}},
        )

        classified_count = 0
        for raw_threat in raw_threats:
            try:
                self.classify_threat(raw_threat)
                classified_count += 1
            except (ValueError, Exception) as exc:
                logger.error(
                    "Failed to classify threat, skipping",
                    extra={"extra_data": {
                        "threat_id": raw_threat.id,
                        "title": raw_threat.title,
                        "error": str(exc),
                    }},
                )

        logger.info(
            "Classification run complete",
            extra={"extra_data": {
                "total": len(raw_threats),
                "classified": classified_count,
                "failed": len(raw_threats) - classified_count,
            }},
        )
        return classified_count
