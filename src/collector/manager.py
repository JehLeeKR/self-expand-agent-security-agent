"""Orchestrates all threat intelligence collectors and stores results.

Features:
- Runs arXiv, RSS, and web collectors concurrently
- Two-layer deduplication: in-memory by source_url + DB-level UNIQUE constraint
- Dynamic query evolution: uses Claude API to suggest new search keywords based
  on recently collected threats, so the search net expands automatically as the
  threat landscape evolves
"""

import asyncio
import json
import os

from src.collector.arxiv import ArxivCollector
from src.collector.cli_search import CLISearchCollector
from src.collector.rss import RSSCollector
from src.collector.search import SearchCollector
from src.collector.web import WebCollector
from src.db.threat_store import ThreatStore
from src.utils.logging import get_logger

logger = get_logger()

QUERY_EVOLUTION_PROMPT = """\
You are an AI security researcher. Based on the recently discovered threat titles below, \
suggest 5-10 NEW search keywords or phrases that would help find RELATED and EMERGING \
threats that our current keyword list might miss.

Current keywords: {current_keywords}

Recently discovered threats:
{recent_threats}

Return a JSON array of strings — only new keywords not already in the current list. \
Focus on novel attack technique names, new vulnerability classes, and emerging jargon \
from the AI security community."""


class CollectorManager:
    """Runs all collectors, deduplicates results, and persists to the threat store.

    On each run, after collection completes, the manager optionally uses Claude
    to suggest new search keywords based on what was found, expanding the search
    net for subsequent runs.
    """

    def __init__(self, threat_store: ThreatStore, config: dict) -> None:
        self.threat_store = threat_store
        self.config = config
        self.collectors = [
            CLISearchCollector(config),  # Claude Code CLI deep research (best quality)
            SearchCollector(config),     # Claude API with web_search tool
            ArxivCollector(config),      # Structured arXiv API queries
            RSSCollector(config),        # RSS/Atom feed monitoring
            WebCollector(config),        # Web scraping + Claude extraction
        ]

    async def run(self) -> int:
        """Execute all collectors and store deduplicated results.

        Returns:
            The number of new threats successfully added to the store.
        """
        all_threats: list[dict] = []

        tasks = [collector.collect() for collector in self.collectors]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for collector, result in zip(self.collectors, results):
            if isinstance(result, BaseException):
                logger.error(
                    "Collector failed entirely",
                    extra={"extra_data": {
                        "collector": collector.source_name,
                        "error": str(result),
                    }},
                )
                continue

            logger.info(
                "Collector returned results",
                extra={"extra_data": {
                    "collector": collector.source_name,
                    "count": len(result),
                }},
            )
            all_threats.extend(
                {**threat, "_source": collector.source_name} for threat in result
            )

        # Deduplicate by source_url, keeping the first occurrence
        seen_urls: set[str] = set()
        unique_threats: list[dict] = []
        for threat in all_threats:
            url = threat.get("source_url", "")
            if url and url in seen_urls:
                continue
            if url:
                seen_urls.add(url)
            unique_threats.append(threat)

        logger.info(
            "Deduplication complete",
            extra={"extra_data": {
                "total_collected": len(all_threats),
                "unique": len(unique_threats),
            }},
        )

        # Store results (DB also deduplicates via UNIQUE(source_url))
        new_count = 0
        for threat in unique_threats:
            try:
                stored = self.threat_store.add_raw_threat(
                    source=threat.get("_source", "unknown"),
                    title=threat.get("title", ""),
                    summary=threat.get("summary", ""),
                    source_url=threat.get("source_url"),
                    raw_content=threat.get("raw_content"),
                )
                if stored is not None:
                    new_count += 1
            except Exception:
                logger.exception(
                    "Failed to store threat",
                    extra={"extra_data": {
                        "title": threat.get("title", ""),
                        "source_url": threat.get("source_url", ""),
                    }},
                )

        logger.info(
            "Collection run complete",
            extra={"extra_data": {
                "new_threats_added": new_count,
                "duplicates_skipped": len(unique_threats) - new_count,
            }},
        )

        # Evolve search queries based on what we found
        if new_count > 0:
            self._evolve_search_queries(unique_threats)

        return new_count

    def _evolve_search_queries(self, recent_threats: list[dict]) -> None:
        """Use Claude to suggest new search keywords based on collected threats.

        New keywords are appended to the in-memory config so subsequent
        collectors (in the same process) pick them up. They are also logged
        for the operator to optionally persist to sources.yaml.
        """
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return

        try:
            from src.utils.claude_api import ClaudeAPI

            current_keywords = self.config.get("ai_security_keywords", [])
            threat_titles = [t.get("title", "") for t in recent_threats[:30]]

            prompt = QUERY_EVOLUTION_PROMPT.format(
                current_keywords=json.dumps(current_keywords),
                recent_threats="\n".join(f"- {t}" for t in threat_titles if t),
            )

            claude = ClaudeAPI()
            new_keywords = claude.query_json(
                "You are a keyword suggestion engine.",
                prompt,
                cache_system_prompt=False,
            )

            if isinstance(new_keywords, list) and new_keywords:
                # Filter out anything already in the current list (case-insensitive)
                existing_lower = {k.lower() for k in current_keywords}
                truly_new = [
                    kw for kw in new_keywords
                    if isinstance(kw, str) and kw.lower() not in existing_lower
                ]

                if truly_new:
                    # Append to in-memory config for this session
                    current_keywords.extend(truly_new)
                    self.config["ai_security_keywords"] = current_keywords

                    logger.info(
                        "Search queries evolved with new keywords",
                        extra={"extra_data": {
                            "new_keywords": truly_new,
                            "total_keywords": len(current_keywords),
                        }},
                    )
                else:
                    logger.info("Query evolution: no new keywords discovered")
            else:
                logger.info("Query evolution: Claude returned no suggestions")

        except Exception:
            logger.exception("Query evolution failed (non-fatal, continuing)")
