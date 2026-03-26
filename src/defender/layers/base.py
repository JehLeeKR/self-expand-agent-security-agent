"""Base classes and data structures for the defense layer framework."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Literal


@dataclass
class DefenseContext:
    """Encapsulates all data flowing through the defense pipeline."""

    input_text: str
    output_text: str | None = None
    context: list[dict] = field(default_factory=list)
    tool_calls: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@dataclass
class DefenseResult:
    """Result returned by a defense layer after inspection."""

    action: Literal["pass", "block", "flag"]
    reason: str | None = None
    modified_text: str | None = None
    confidence: float = 0.0


@dataclass
class DetectionRule:
    """A single detection rule used by a defense layer."""

    name: str
    pattern: str
    description: str
    severity: str  # "low", "medium", "high", "critical"


class BaseDefenseLayer(ABC):
    """Abstract base class for all defense layers in the pipeline."""

    name: str
    priority: int
    threat_categories: list[str]

    @abstractmethod
    async def inspect(self, data: DefenseContext) -> DefenseResult:
        """Inspect the given context and return a defense result.

        Args:
            data: The defense context containing input, output, tool calls, etc.

        Returns:
            A DefenseResult indicating pass, block, or flag.
        """

    @abstractmethod
    def get_rules(self) -> list[DetectionRule]:
        """Return the list of detection rules used by this layer."""
