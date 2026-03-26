"""Orchestrates all threat intelligence collectors and stores results."""

import asyncio

from src.collector.arxiv import ArxivCollector
from src.collector.rss import RSSCollector
from src.collector.web import WebCollector
from src.db.threat_store import ThreatStore
from src.utils.logging import get_logger

logger = get_logger()


class CollectorManager:
    """Runs all collectors, deduplicates results, and persists to the threat store."""

    def __init__(self, threat_store: ThreatStore, config: dict) -> None:
        self.threat_store = threat_store
        self.config = config
        self.collectors = [
            ArxivCollector(config),
            RSSCollector(config),
            WebCollector(config),
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

        # Store results
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
        return new_count
