"""Abstract base class for threat intelligence collectors."""

from abc import ABC, abstractmethod


class BaseCollector(ABC):
    """Base class that all threat intelligence collectors must implement."""

    def __init__(self, config: dict) -> None:
        self.config = config

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Unique identifier for this collection source."""

    @abstractmethod
    async def collect(self) -> list[dict]:
        """Collect threat intelligence from the source.

        Returns:
            A list of dicts, each containing:
                - title: str
                - summary: str
                - source_url: str
                - raw_content: str
        """
