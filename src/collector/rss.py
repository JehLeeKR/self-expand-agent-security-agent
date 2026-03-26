"""Collector for AI security threat intelligence from RSS/Atom feeds."""

import asyncio

import feedparser

from src.collector.base import BaseCollector
from src.utils.logging import get_logger

logger = get_logger()


class RSSCollector(BaseCollector):
    """Parses configured RSS/Atom feeds and filters by AI security keywords."""

    @property
    def source_name(self) -> str:
        return "rss"

    def _matches_keywords(self, title: str, summary: str) -> bool:
        """Check whether the title or summary contains any AI security keyword."""
        keywords = self.config.get("ai_security_keywords", [])
        text = f"{title} {summary}".lower()
        return any(kw.lower() in text for kw in keywords)

    def _fetch_feeds(self) -> list[dict]:
        """Synchronously parse all configured feeds and filter entries."""
        feeds = self.config.get("rss_feeds", [])
        results: list[dict] = []
        seen_urls: set[str] = set()

        for feed_cfg in feeds:
            name = feed_cfg.get("name", "unknown")
            url = feed_cfg.get("url", "")

            try:
                parsed = feedparser.parse(url)

                if parsed.bozo and not parsed.entries:
                    logger.warning(
                        "Feed parse error with no entries",
                        extra={"extra_data": {"feed": name, "error": str(parsed.bozo_exception)}},
                    )
                    continue

                for entry in parsed.entries:
                    title = entry.get("title", "")
                    summary = entry.get("summary", entry.get("description", ""))
                    link = entry.get("link", "")

                    if not link or link in seen_urls:
                        continue

                    if not self._matches_keywords(title, summary):
                        continue

                    seen_urls.add(link)
                    results.append({
                        "title": title,
                        "summary": summary,
                        "source_url": link,
                        "raw_content": (
                            f"Feed: {name}\n"
                            f"Category: {feed_cfg.get('category', 'unknown')}\n"
                            f"Title: {title}\n\n"
                            f"{summary}"
                        ),
                    })

            except Exception:
                logger.exception(
                    "Failed to parse RSS feed",
                    extra={"extra_data": {"feed": name, "url": url}},
                )

        logger.info(
            "RSS collection complete",
            extra={"extra_data": {"matching_entries": len(results)}},
        )
        return results

    async def collect(self) -> list[dict]:
        """Collect entries from RSS feeds, running blocking I/O in a thread."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._fetch_feeds)
