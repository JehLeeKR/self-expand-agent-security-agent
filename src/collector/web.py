"""Collector for AI security threat intelligence from web pages using Claude Code CLI.

Instead of raw HTTP scraping (which hits bot defenses, CAPTCHAs, JS-rendered
pages), this collector delegates web fetching entirely to Claude Code CLI.
The CLI's built-in web fetch handles anti-bot measures, renders JavaScript,
and follows redirects — then Claude analyzes the content in-context, providing:

- Threat extraction and summarization
- Technical interpretation of vulnerabilities
- Gap analysis against known defense techniques
- Implementation advice for defense layers

This gives each web source the same research quality as an interactive Claude
chat session, rather than brittle HTML scraping.
"""

import asyncio
import json
import subprocess

from src.collector.base import BaseCollector
from src.utils.logging import get_logger

logger = get_logger()

_SOURCE_RESEARCH_PROMPT = """\
You are an expert AI/LLM security threat researcher. Visit and thoroughly read \
the following web page, then extract ALL relevant AI agent security threats, \
vulnerabilities, attack techniques, and defensive research findings.

URL: {url}
Source name: {source_name}

Instructions:
1. Fetch and read the full page content at the URL above
2. Identify every item related to AI/LLM agent security threats
3. For each threat found, provide:
   - title: Concise descriptive title
   - summary: 2-5 sentence technical description of the threat
   - source_url: The specific URL where you found it (may differ from the \
page URL if you follow links)
   - raw_content: Detailed technical analysis including:
     * How the attack works (mechanism)
     * What components are affected (input/output/context/tools/storage)
     * Known mitigations or defense gaps
     * Implementation advice for building defenses against it
4. If the page links to related papers, advisories, or PoCs — follow those \
links and include findings from them too

Return your findings as a JSON array:
[{{"title": "...", "summary": "...", "source_url": "...", "raw_content": "..."}}]

If no relevant AI security threats are found on the page, return an empty array: []

Be thorough. Extract technical details, not just headlines. Include your \
assessment of severity and novelty for each finding."""

_BATCH_RESEARCH_PROMPT = """\
You are an expert AI/LLM security threat researcher. I need you to visit \
multiple web sources and extract AI agent security threat intelligence from each.

Sources to research:
{sources_list}

For EACH source:
1. Visit the URL and read the full page content
2. Follow any links to related papers, advisories, or proof-of-concepts
3. Extract all AI/LLM security threats, vulnerabilities, and attack techniques

For each threat you find, provide:
- title: Concise descriptive title
- summary: 2-5 sentence technical description
- source_url: The specific URL where you found it
- raw_content: Detailed analysis including attack mechanism, affected \
components, known mitigations, defense gaps, and implementation advice

Also identify:
- Gaps in current defense approaches mentioned in these sources
- Novel attack vectors not yet widely discussed
- Cross-source patterns (same threat discussed from different angles)

Return ALL findings as a single JSON array:
[{{"title": "...", "summary": "...", "source_url": "...", "raw_content": "..."}}]

Be thorough and technical. Quality over quantity — include real details, \
not just headlines."""


class WebCollector(BaseCollector):
    """Uses Claude Code CLI to fetch and analyze web sources for threat intelligence.

    The CLI handles bot defenses, JavaScript rendering, and anti-scraping
    measures natively. Claude then provides in-context technical analysis,
    gap identification, and implementation advice — far richer than what
    raw HTML scraping + separate extraction could achieve.
    """

    def __init__(self, config: dict) -> None:
        super().__init__(config)
        cli_config = config.get("claude_code", {})
        self.binary = cli_config.get("binary", "claude")
        self.timeout = cli_config.get("timeout_seconds", 300)
        # Max sources per batch to keep CLI context manageable
        self.batch_size = cli_config.get("web_batch_size", 3)

    @property
    def source_name(self) -> str:
        return "web"

    def _run_cli(self, prompt: str) -> list[dict]:
        """Invoke Claude Code CLI with a research prompt and parse results."""
        cmd = [
            self.binary,
            "-p", prompt,
            "--output-format", "json",
        ]

        logger.info(
            "Invoking Claude CLI for web research",
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
                    "Claude CLI web research failed",
                    extra={"extra_data": {"stderr": result.stderr[:500]}},
                )
                return []

            return self._parse_cli_output(result.stdout)

        except subprocess.TimeoutExpired:
            logger.warning(
                "Claude CLI web research timed out",
                extra={"extra_data": {"timeout": self.timeout}},
            )
            return []
        except FileNotFoundError:
            logger.warning(
                "Claude CLI binary not found — web collection disabled",
                extra={"extra_data": {"binary": self.binary}},
            )
            return []

    def _parse_cli_output(self, output: str) -> list[dict]:
        """Parse Claude CLI JSON output to extract threat findings."""
        if not output.strip():
            return []

        try:
            cli_response = json.loads(output)
        except json.JSONDecodeError:
            return self._extract_json_array(output)

        # Extract text from the CLI JSON envelope
        if isinstance(cli_response, dict):
            text = cli_response.get("result", "")
            if not text:
                text = json.dumps(cli_response)
        elif isinstance(cli_response, list):
            return self._validate_threats(cli_response)
        else:
            text = str(cli_response)

        return self._extract_json_array(text)

    def _extract_json_array(self, text: str) -> list[dict]:
        """Find and parse a JSON array from text output."""
        cleaned = text.strip()

        # Remove markdown code fences if present
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0]
        elif "```" in cleaned:
            parts = cleaned.split("```")
            if len(parts) >= 3:
                cleaned = parts[1]

        start = cleaned.find("[")
        end = cleaned.rfind("]")
        if start == -1 or end == -1:
            logger.warning("No JSON array found in CLI web research output")
            return []

        try:
            items = json.loads(cleaned[start:end + 1])
            return self._validate_threats(items)
        except json.JSONDecodeError:
            logger.warning("Failed to parse JSON array from CLI web output")
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

    def _research_single_source(self, name: str, url: str) -> list[dict]:
        """Research a single web source via Claude CLI."""
        prompt = _SOURCE_RESEARCH_PROMPT.format(url=url, source_name=name)
        threats = self._run_cli(prompt)

        logger.info(
            "Single source research complete",
            extra={"extra_data": {
                "source": name,
                "url": url,
                "threats_found": len(threats),
            }},
        )
        return threats

    def _research_batch(self, sources: list[dict]) -> list[dict]:
        """Research multiple web sources in a single CLI call."""
        sources_list = "\n".join(
            f"- {s.get('name', 'unknown')}: {s.get('url', '')}"
            for s in sources
        )
        prompt = _BATCH_RESEARCH_PROMPT.format(sources_list=sources_list)
        threats = self._run_cli(prompt)

        logger.info(
            "Batch source research complete",
            extra={"extra_data": {
                "sources": [s.get("name") for s in sources],
                "threats_found": len(threats),
            }},
        )
        return threats

    async def collect(self) -> list[dict]:
        """Fetch and analyze all configured web sources via Claude CLI.

        Sources are processed in batches to keep CLI context manageable.
        Each batch gets a single CLI call that visits all URLs in the batch,
        follows links, and provides cross-source analysis.
        """
        web_sources = self.config.get("web_sources", [])
        if not web_sources:
            logger.info("No web sources configured, skipping")
            return []

        logger.info(
            "Starting CLI-based web collection",
            extra={"extra_data": {"source_count": len(web_sources)}},
        )

        loop = asyncio.get_running_loop()
        all_results: list[dict] = []

        # Process in batches
        for i in range(0, len(web_sources), self.batch_size):
            batch = web_sources[i:i + self.batch_size]

            if len(batch) == 1:
                source = batch[0]
                threats = await loop.run_in_executor(
                    None,
                    self._research_single_source,
                    source.get("name", "unknown"),
                    source.get("url", ""),
                )
            else:
                threats = await loop.run_in_executor(
                    None,
                    self._research_batch,
                    batch,
                )

            all_results.extend(threats)

        logger.info(
            "Web collection complete",
            extra={"extra_data": {"threats_extracted": len(all_results)}},
        )
        return all_results
