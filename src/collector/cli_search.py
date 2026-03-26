"""Threat intelligence collector using Claude Code CLI for deep research.

This collector invokes `claude -p` (the Claude Code CLI) to perform research.
The CLI has built-in web search, file reading, and tool use capabilities —
giving the agent the same research power as an interactive Claude Code session.

Key advantage over the API-based SearchCollector: the CLI manages its own
tool loop (search, fetch, read) internally, so we get multi-step research
"for free" without implementing tool-use orchestration ourselves.

Usage:
    The CLI must be available on PATH (or configured in default.yaml).
    Set ANTHROPIC_API_KEY in the environment.
"""

import asyncio
import json
import subprocess

from src.collector.base import BaseCollector
from src.utils.logging import get_logger

logger = get_logger()

RESEARCH_PROMPT_TEMPLATE = """\
You are an AI security threat researcher. Search the web thoroughly for the \
most recent AI/LLM agent security threats, vulnerabilities, and attack \
techniques discovered in the last 2 weeks.

Focus areas: {keywords}

Search multiple sources:
- Recent arXiv papers on AI security
- Security researcher blogs (Simon Willison, etc.)
- Vendor security advisories (Anthropic, OpenAI, Google, Microsoft)
- Conference talks and proceedings (BlackHat, DEF CON AI Village, USENIX)
- OWASP LLM Top 10 updates
- MITRE ATLAS updates
- Hacker News and Reddit discussions on AI security

For each threat you discover, provide these details:
- title: Short descriptive title
- summary: 2-5 sentence description of the threat
- source_url: The URL where you found it
- raw_content: Full details including how the attack works

Return your findings as a JSON array:
[{{"title": "...", "summary": "...", "source_url": "...", "raw_content": "..."}}]

Search broadly and deeply. Follow references. Cross-check findings. \
Quality and recency matter — only include threats from the last 2 weeks."""

FOLLOWUP_PROMPT_TEMPLATE = """\
I previously found these AI security threats:
{previous_findings}

Now do a DEEPER follow-up search:
1. Search for related attack variations and techniques
2. Look for proof-of-concept implementations
3. Find defensive research or proposed mitigations
4. Check community discussions for emerging angles we missed

Return ONLY NEW findings (not duplicates) as a JSON array:
[{{"title": "...", "summary": "...", "source_url": "...", "raw_content": "..."}}]"""


class CLISearchCollector(BaseCollector):
    """Uses Claude Code CLI (`claude -p`) for AI-powered threat research.

    The CLI handles its own web search and multi-step reasoning internally,
    giving us research quality comparable to an interactive Claude session.
    """

    def __init__(self, config: dict) -> None:
        super().__init__(config)
        cli_config = config.get("claude_code", {})
        self.binary = cli_config.get("binary", "claude")
        self.timeout = cli_config.get("research_timeout_seconds", 600)

    @property
    def source_name(self) -> str:
        return "cli_search"

    def _run_cli_research(self, prompt: str) -> list[dict]:
        """Invoke Claude CLI with a research prompt and parse results."""
        cmd = [
            self.binary,
            "-p", prompt,
            "--output-format", "json",
        ]

        logger.info(
            "Invoking Claude CLI for research",
            extra={"extra_data": {"prompt_length": len(prompt)}},
        )

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            if result.returncode != 0:
                logger.error(
                    "Claude CLI research failed",
                    extra={"extra_data": {"stderr": result.stderr[:500]}},
                )
                return []

            return self._parse_cli_output(result.stdout)

        except subprocess.TimeoutExpired:
            logger.warning(
                "Claude CLI research timed out",
                extra={"extra_data": {"timeout": self.timeout}},
            )
            return []
        except FileNotFoundError:
            logger.warning(
                "Claude CLI binary not found",
                extra={"extra_data": {"binary": self.binary}},
            )
            return []

    def _parse_cli_output(self, output: str) -> list[dict]:
        """Parse Claude CLI JSON output to extract threat findings."""
        if not output.strip():
            return []

        # The CLI --output-format json wraps output in a JSON structure.
        # The actual research results are in the text content.
        try:
            cli_response = json.loads(output)
        except json.JSONDecodeError:
            # Might be plain text if --output-format wasn't recognized
            return self._extract_json_array(output)

        # Extract text from the CLI JSON envelope
        if isinstance(cli_response, dict):
            # CLI format: {"result": "...", ...} or similar
            text = cli_response.get("result", "")
            if not text:
                # Try to find text in nested structures
                text = json.dumps(cli_response)
        elif isinstance(cli_response, list):
            # Might already be the threat array
            return self._validate_threats(cli_response)
        else:
            text = str(cli_response)

        return self._extract_json_array(text)

    def _extract_json_array(self, text: str) -> list[dict]:
        """Find and parse a JSON array from text output."""
        # Remove markdown code fences if present
        cleaned = text.strip()
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0]
        elif "```" in cleaned:
            parts = cleaned.split("```")
            if len(parts) >= 3:
                cleaned = parts[1]

        # Find the JSON array
        start = cleaned.find("[")
        end = cleaned.rfind("]")
        if start == -1 or end == -1:
            logger.warning("No JSON array found in CLI output")
            return []

        try:
            items = json.loads(cleaned[start:end + 1])
            return self._validate_threats(items)
        except json.JSONDecodeError:
            logger.warning("Failed to parse JSON array from CLI output")
            return []

    def _validate_threats(self, items: list) -> list[dict]:
        """Validate and normalize threat entries."""
        results = []
        for item in items:
            if not isinstance(item, dict):
                continue
            title = item.get("title", "")
            summary = item.get("summary", "")
            if title and summary:
                results.append({
                    "title": title,
                    "summary": summary,
                    "source_url": item.get("source_url", ""),
                    "raw_content": item.get("raw_content", f"{title}\n\n{summary}"),
                })
        return results

    async def collect(self) -> list[dict]:
        """Run CLI-based threat research with two rounds.

        Round 1: Broad search across all configured keyword areas
        Round 2: Deep dive follow-up on initial findings
        """
        search_config = self.config.get("search", {})
        if not search_config.get("cli_enabled", True):
            logger.info("CLI search collector disabled, skipping")
            return []

        # Build the research prompt with current keywords
        keywords = self.config.get("ai_security_keywords", [])
        keyword_str = ", ".join(keywords[:20]) if keywords else "AI agent security"

        prompt = RESEARCH_PROMPT_TEMPLATE.format(keywords=keyword_str)

        logger.info("Starting CLI-based threat research (round 1)")

        loop = asyncio.get_running_loop()
        initial = await loop.run_in_executor(None, self._run_cli_research, prompt)

        logger.info(
            "CLI research round 1 complete",
            extra={"extra_data": {"threats_found": len(initial)}},
        )

        # Round 2: deep dive if we found threats
        all_results = list(initial)
        if initial and search_config.get("deep_dive", True):
            previous = json.dumps(
                [{"title": r["title"], "summary": r["summary"]} for r in initial[:10]],
                indent=2,
            )
            followup = FOLLOWUP_PROMPT_TEMPLATE.format(previous_findings=previous)

            logger.info("Starting CLI research round 2 (deep dive)")
            deep = await loop.run_in_executor(None, self._run_cli_research, followup)

            logger.info(
                "CLI research round 2 complete",
                extra={"extra_data": {"additional_threats": len(deep)}},
            )
            all_results.extend(deep)

        logger.info(
            "CLI search collection complete",
            extra={"extra_data": {"total_threats": len(all_results)}},
        )
        return all_results
