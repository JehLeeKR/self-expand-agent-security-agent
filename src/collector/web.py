"""Collector for AI security threat intelligence from web pages."""

import aiohttp
from bs4 import BeautifulSoup

from src.collector.base import BaseCollector
from src.utils.claude_api import ClaudeAPI
from src.utils.logging import get_logger

logger = get_logger()

EXTRACTION_SYSTEM_PROMPT = (
    "You are a threat intelligence analyst specializing in AI and LLM security. "
    "Extract structured threat information from the provided web page content. "
    "Return a JSON array of objects, each with keys: "
    '"title" (short threat title), '
    '"summary" (1-3 sentence description of the threat or finding). '
    "Only include items that are relevant to AI/LLM security threats, vulnerabilities, "
    "or attack techniques. If no relevant threats are found, return an empty array []."
)

MAX_CONTENT_LENGTH = 12000


class WebCollector(BaseCollector):
    """Scrapes configured web sources and uses Claude to extract threat intelligence."""

    def __init__(self, config: dict) -> None:
        super().__init__(config)
        self._claude: ClaudeAPI | None = None

    @property
    def claude(self) -> ClaudeAPI:
        if self._claude is None:
            self._claude = ClaudeAPI()
        return self._claude

    @property
    def source_name(self) -> str:
        return "web"

    @staticmethod
    def _extract_text(html: str) -> str:
        """Strip HTML tags and return cleaned text, truncated to a reasonable size."""
        soup = BeautifulSoup(html, "html.parser")

        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()

        text = soup.get_text(separator="\n", strip=True)
        if len(text) > MAX_CONTENT_LENGTH:
            text = text[:MAX_CONTENT_LENGTH] + "\n...[truncated]"
        return text

    async def _fetch_page(self, session: aiohttp.ClientSession, url: str) -> str:
        """Fetch a single web page and return its HTML."""
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            resp.raise_for_status()
            return await resp.text()

    def _extract_threats(self, source_name: str, source_url: str, text: str) -> list[dict]:
        """Use Claude to extract threat intelligence from page text."""
        user_message = (
            f"Source: {source_name}\nURL: {source_url}\n\n"
            f"Page content:\n{text}"
        )

        try:
            extracted = self.claude.query_json(EXTRACTION_SYSTEM_PROMPT, user_message)
        except Exception:
            logger.exception(
                "Claude extraction failed",
                extra={"extra_data": {"source": source_name, "url": source_url}},
            )
            return []

        if not isinstance(extracted, list):
            logger.warning(
                "Claude returned non-list response, skipping",
                extra={"extra_data": {"source": source_name}},
            )
            return []

        results: list[dict] = []
        for item in extracted:
            if not isinstance(item, dict):
                continue
            title = item.get("title", "")
            summary = item.get("summary", "")
            if title and summary:
                results.append({
                    "title": title,
                    "summary": summary,
                    "source_url": source_url,
                    "raw_content": (
                        f"Source: {source_name}\n"
                        f"Type: web_extraction\n"
                        f"Title: {title}\n\n"
                        f"{summary}\n\n"
                        f"---\nOriginal page text (excerpt):\n{text[:2000]}"
                    ),
                })

        return results

    async def collect(self) -> list[dict]:
        """Fetch all configured web sources and extract threat intelligence."""
        web_sources = self.config.get("web_sources", [])
        results: list[dict] = []

        async with aiohttp.ClientSession(
            headers={"User-Agent": "ThreatDefenseAgent/1.0"},
        ) as session:
            for source in web_sources:
                name = source.get("name", "unknown")
                url = source.get("url", "")

                try:
                    html = await self._fetch_page(session, url)
                    text = self._extract_text(html)

                    if not text.strip():
                        logger.warning(
                            "Empty page content after extraction",
                            extra={"extra_data": {"source": name, "url": url}},
                        )
                        continue

                    threats = self._extract_threats(name, url, text)
                    results.extend(threats)

                except Exception:
                    logger.exception(
                        "Failed to collect from web source",
                        extra={"extra_data": {"source": name, "url": url}},
                    )

        logger.info(
            "Web collection complete",
            extra={"extra_data": {"threats_extracted": len(results)}},
        )
        return results
