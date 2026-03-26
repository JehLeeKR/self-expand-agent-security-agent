"""Collector for AI security research papers from arXiv."""

import asyncio
from datetime import datetime, timedelta, timezone

import arxiv

from src.collector.base import BaseCollector
from src.utils.logging import get_logger

logger = get_logger()


class ArxivCollector(BaseCollector):
    """Fetches recent papers from arXiv matching AI security topics."""

    @property
    def source_name(self) -> str:
        return "arxiv"

    def _build_queries(self) -> list[str]:
        """Build arXiv API query strings from configured categories and keywords."""
        arxiv_config = self.config.get("arxiv", {})
        categories = arxiv_config.get("categories", [])
        keywords = arxiv_config.get("keywords", [])

        queries = []
        for keyword in keywords:
            cat_filter = " OR ".join(f"cat:{cat}" for cat in categories)
            query = f'({cat_filter}) AND all:"{keyword}"'
            queries.append(query)

        return queries

    def _fetch_papers(self) -> list[dict]:
        """Synchronously fetch papers via the arxiv package."""
        arxiv_config = self.config.get("arxiv", {})
        max_results = arxiv_config.get("max_results_per_query", 20)
        lookback_days = arxiv_config.get("lookback_days", 7)
        cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)

        queries = self._build_queries()
        client = arxiv.Client()
        seen_ids: set[str] = set()
        results: list[dict] = []

        for query in queries:
            try:
                search = arxiv.Search(
                    query=query,
                    max_results=max_results,
                    sort_by=arxiv.SortCriterion.SubmittedDate,
                    sort_order=arxiv.SortOrder.Descending,
                )

                for paper in client.results(search):
                    published = paper.published.replace(tzinfo=timezone.utc)
                    if published < cutoff:
                        continue

                    entry_id = paper.entry_id
                    if entry_id in seen_ids:
                        continue
                    seen_ids.add(entry_id)

                    results.append({
                        "title": paper.title,
                        "summary": paper.summary,
                        "source_url": entry_id,
                        "raw_content": (
                            f"Title: {paper.title}\n"
                            f"Authors: {', '.join(a.name for a in paper.authors)}\n"
                            f"Published: {published.isoformat()}\n"
                            f"Categories: {', '.join(paper.categories)}\n\n"
                            f"Abstract:\n{paper.summary}"
                        ),
                    })

            except Exception:
                logger.exception(
                    "Failed to fetch arXiv results for query",
                    extra={"extra_data": {"query": query}},
                )

        logger.info(
            "ArXiv collection complete",
            extra={"extra_data": {"papers_found": len(results)}},
        )
        return results

    async def collect(self) -> list[dict]:
        """Collect papers from arXiv, running the blocking API call in a thread."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._fetch_papers)
