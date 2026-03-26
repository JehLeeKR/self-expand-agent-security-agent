"""AI-powered deep search collector using Claude's tool_use for web research.

This collector leverages Claude's ability to perform multi-step research by
using the Anthropic API with web search tools. This gives the agent search
quality comparable to using Claude interactively in the chat UI — the AI
decides what to search for, follows leads, cross-references sources, and
synthesizes findings.

Requires: ANTHROPIC_API_KEY environment variable.

Architecture:
1. Claude is given a research task (e.g., "find recent AI agent security threats")
2. Claude autonomously performs multiple web searches via the `web_search` tool
3. Claude synthesizes findings into structured threat intelligence
4. Results flow into the same pipeline as other collectors
"""

import asyncio
import json
import os

import anthropic

from src.collector.base import BaseCollector
from src.utils.logging import get_logger

logger = get_logger()

RESEARCH_SYSTEM_PROMPT = """\
You are an expert AI security threat researcher. Your task is to find the most \
recent and significant threats, vulnerabilities, and attack techniques targeting \
AI/LLM-based agent systems.

Search broadly across:
- Academic preprint servers and research blogs
- AI security conference proceedings and talks
- Vendor security advisories and blog posts
- Security researcher blogs and social media discussions
- Bug bounty disclosures related to AI systems
- Red team reports and CTF writeups involving AI/LLM

Focus on threats from the last 2 weeks. Prioritize:
1. Novel attack techniques not widely known
2. Actively exploited vulnerabilities
3. New categories of risk for agentic AI systems
4. Defensive bypasses for existing protections

For each threat you find, provide:
- A clear title
- A detailed summary (2-5 sentences)
- The source URL
- Why it matters for AI agent security

Return your findings as a JSON array:
[{{"title": "...", "summary": "...", "source_url": "...", "raw_content": "..."}}]
"""

DEEP_DIVE_PROMPT = """\
Based on these previously identified threat areas, do a DEEPER search to find:
1. Related techniques or variations
2. Proof-of-concept code or demonstrations
3. Defensive research or mitigations being proposed
4. Community discussions revealing new angles

Previous findings:
{previous_findings}

Search for follow-up information and return additional threats as a JSON array. \
Only include NEW findings not already in the previous list."""


class SearchCollector(BaseCollector):
    """Uses Claude with web search tools for AI-powered threat research.

    This gives the agent the same deep research capability as an interactive
    Claude chat session — the AI autonomously decides what to search for,
    follows chains of references, and synthesizes findings.
    """

    def __init__(self, config: dict) -> None:
        super().__init__(config)
        self._client: anthropic.Anthropic | None = None

    @property
    def source_name(self) -> str:
        return "ai_search"

    @property
    def client(self) -> anthropic.Anthropic:
        if self._client is None:
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            self._client = anthropic.Anthropic(api_key=api_key)
        return self._client

    def _research_with_search(self, prompt: str, system: str) -> list[dict]:
        """Run a research session with Claude using web search tools.

        Claude will autonomously perform web searches to gather threat
        intelligence, then return structured results.
        """
        search_config = self.config.get("search", {})
        model = search_config.get("model", "claude-sonnet-4-6")
        max_tokens = search_config.get("max_tokens", 16000)

        try:
            response = self.client.messages.create(
                model=model,
                max_tokens=max_tokens,
                system=[{
                    "type": "text",
                    "text": system,
                    "cache_control": {"type": "ephemeral"},
                }],
                tools=[{
                    "type": "web_search_20250305",
                    "name": "web_search",
                    "max_uses": search_config.get("max_searches_per_session", 20),
                }],
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.BadRequestError as exc:
            # web_search tool may not be available on all plans/models
            logger.warning(
                "Web search tool not available, falling back to knowledge-only mode",
                extra={"extra_data": {"error": str(exc)}},
            )
            return self._research_without_search(prompt, system)
        except Exception:
            logger.exception("Search research session failed")
            return []

        # Extract the final text response (after all tool use rounds)
        text_parts = []
        for block in response.content:
            if hasattr(block, "text"):
                text_parts.append(block.text)

        full_text = "\n".join(text_parts)
        return self._parse_research_output(full_text)

    def _research_without_search(self, prompt: str, system: str) -> list[dict]:
        """Fallback: use Claude's training knowledge without live search."""
        try:
            response = self.client.messages.create(
                model=self.config.get("search", {}).get("model", "claude-sonnet-4-6"),
                max_tokens=8000,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
            text = response.content[0].text
            return self._parse_research_output(text)
        except Exception:
            logger.exception("Fallback research session failed")
            return []

    def _parse_research_output(self, text: str) -> list[dict]:
        """Parse Claude's research output into structured threat dicts."""
        # Find JSON array in the response
        cleaned = text.strip()

        # Try to extract JSON from various formats
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0]
        elif "```" in cleaned:
            cleaned = cleaned.split("```")[1].split("```")[0]

        # Find the JSON array
        start = cleaned.find("[")
        end = cleaned.rfind("]")
        if start == -1 or end == -1:
            logger.warning("No JSON array found in research output")
            return []

        try:
            items = json.loads(cleaned[start:end + 1])
        except json.JSONDecodeError:
            logger.warning("Failed to parse research output JSON")
            return []

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
        """Run AI-powered threat research with optional web search.

        Performs two rounds:
        1. Broad search for recent AI agent security threats
        2. Deep dive follow-up based on initial findings

        This mirrors how a human researcher would use Claude chat: ask a broad
        question, review results, then ask targeted follow-ups.
        """
        search_config = self.config.get("search", {})
        enabled = search_config.get("enabled", True)
        if not enabled or not os.environ.get("ANTHROPIC_API_KEY"):
            logger.info("Search collector disabled or no API key, skipping")
            return []

        # Build focused search prompt from configured keywords
        keywords = self.config.get("ai_security_keywords", [])
        keyword_context = ", ".join(keywords[:15]) if keywords else "AI agent security threats"

        research_prompt = (
            f"Search for the most recent AI/LLM agent security threats, focusing on: "
            f"{keyword_context}.\n\n"
            f"Look for threats published or discussed in the last 2 weeks. "
            f"Search multiple sources: research papers, security blogs, vendor advisories, "
            f"conference talks, and community discussions."
        )

        logger.info("Starting AI-powered threat research (round 1: broad search)")

        loop = asyncio.get_running_loop()
        initial_results = await loop.run_in_executor(
            None,
            self._research_with_search,
            research_prompt,
            RESEARCH_SYSTEM_PROMPT,
        )

        logger.info(
            "Round 1 complete",
            extra={"extra_data": {"threats_found": len(initial_results)}},
        )

        # Round 2: deep dive if we found anything
        all_results = list(initial_results)
        if initial_results and search_config.get("deep_dive", True):
            previous = json.dumps(
                [{"title": r["title"], "summary": r["summary"]} for r in initial_results[:10]],
                indent=2,
            )
            deep_prompt = DEEP_DIVE_PROMPT.format(previous_findings=previous)

            logger.info("Starting deep dive research (round 2)")
            deep_results = await loop.run_in_executor(
                None,
                self._research_with_search,
                deep_prompt,
                RESEARCH_SYSTEM_PROMPT,
            )

            logger.info(
                "Round 2 complete",
                extra={"extra_data": {"additional_threats": len(deep_results)}},
            )
            all_results.extend(deep_results)

        logger.info(
            "AI search collection complete",
            extra={"extra_data": {"total_threats": len(all_results)}},
        )
        return all_results
