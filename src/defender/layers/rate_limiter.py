"""Rate limiting defense layer for detecting anomalous request bursts."""

import time
from collections import defaultdict

from src.defender.layers.base import (
    BaseDefenseLayer,
    DefenseContext,
    DefenseResult,
    DetectionRule,
)
from src.utils.logging import get_logger

logger = get_logger()


class _SlidingWindowCounter:
    """Sliding-window rate counter for a single session.

    Tracks event timestamps within a configurable window and provides
    current count / rate metrics.
    """

    def __init__(self, window_seconds: float = 60.0) -> None:
        self.window_seconds = window_seconds
        self._timestamps: list[float] = []

    def record(self, ts: float | None = None) -> None:
        ts = ts if ts is not None else time.monotonic()
        self._timestamps.append(ts)

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        # Remove expired entries from the front.
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.pop(0)

    def count(self, now: float | None = None) -> int:
        now = now if now is not None else time.monotonic()
        self._prune(now)
        return len(self._timestamps)

    def rate_per_second(self, now: float | None = None) -> float:
        now = now if now is not None else time.monotonic()
        c = self.count(now)
        return c / self.window_seconds if self.window_seconds > 0 else 0.0


class RateLimiter(BaseDefenseLayer):
    """Tracks request patterns per session and flags anomalous bursts.

    Priority: 40 (runs after tool sandbox, before output filter).
    """

    name: str = "rate_limiter"
    priority: int = 40
    threat_categories: list[str] = ["tool_abuse", "data_exfiltration"]

    def __init__(
        self,
        window_seconds: float = 60.0,
        max_requests_per_window: int = 30,
        max_tool_calls_per_window: int = 60,
        max_data_bytes_per_window: int = 500_000,
        burst_factor: float = 3.0,
    ) -> None:
        self.window_seconds = window_seconds
        self.max_requests_per_window = max_requests_per_window
        self.max_tool_calls_per_window = max_tool_calls_per_window
        self.max_data_bytes_per_window = max_data_bytes_per_window
        self.burst_factor = burst_factor

        # Per-session counters.
        self._request_counters: dict[str, _SlidingWindowCounter] = defaultdict(
            lambda: _SlidingWindowCounter(window_seconds)
        )
        self._tool_call_counters: dict[str, _SlidingWindowCounter] = defaultdict(
            lambda: _SlidingWindowCounter(window_seconds)
        )
        self._data_bytes: dict[str, _SlidingWindowCounter] = defaultdict(
            lambda: _SlidingWindowCounter(window_seconds)
        )

    def _get_session_id(self, data: DefenseContext) -> str:
        return data.metadata.get("session_id", "__default__")

    def _estimate_data_size(self, data: DefenseContext) -> int:
        size = len(data.input_text.encode("utf-8", errors="replace")) if data.input_text else 0
        if data.output_text:
            size += len(data.output_text.encode("utf-8", errors="replace"))
        for call in data.tool_calls:
            size += len(str(call).encode("utf-8", errors="replace"))
        return size

    async def inspect(self, data: DefenseContext) -> DefenseResult:
        session_id = self._get_session_id(data)
        now = time.monotonic()
        issues: list[str] = []
        max_severity: float = 0.0

        # Record the current request.
        self._request_counters[session_id].record(now)
        req_count = self._request_counters[session_id].count(now)

        if req_count > self.max_requests_per_window:
            severity = min((req_count / self.max_requests_per_window - 1.0) * 0.5 + 0.6, 1.0)
            issues.append(
                f"Request rate exceeded: {req_count}/{self.max_requests_per_window} per window"
            )
            max_severity = max(max_severity, severity)

        # Record tool calls.
        num_tool_calls = len(data.tool_calls)
        for _ in range(num_tool_calls):
            self._tool_call_counters[session_id].record(now)
        tool_count = self._tool_call_counters[session_id].count(now)

        if tool_count > self.max_tool_calls_per_window:
            severity = min((tool_count / self.max_tool_calls_per_window - 1.0) * 0.5 + 0.6, 1.0)
            issues.append(
                f"Tool call rate exceeded: {tool_count}/{self.max_tool_calls_per_window} per window"
            )
            max_severity = max(max_severity, severity)

        # Burst detection: check if the last few seconds have disproportionate activity.
        short_window = _SlidingWindowCounter(window_seconds=5.0)
        # Approximate: count entries within the last 5 seconds from the request counter.
        for ts in self._request_counters[session_id]._timestamps:
            if ts >= now - 5.0:
                short_window.record(ts)
        short_count = short_window.count(now)
        expected_in_5s = (self.max_requests_per_window / self.window_seconds) * 5.0
        if expected_in_5s > 0 and short_count > expected_in_5s * self.burst_factor:
            issues.append(
                f"Request burst detected: {short_count} requests in 5s "
                f"(expected ~{expected_in_5s:.1f})"
            )
            max_severity = max(max_severity, 0.75)

        # Data volume check.
        data_size = self._estimate_data_size(data)
        # We use a simple counter where each "event" represents ~1KB.
        kb_units = max(data_size // 1024, 1)
        for _ in range(kb_units):
            self._data_bytes[session_id].record(now)
        total_kb = self._data_bytes[session_id].count(now)
        max_kb = self.max_data_bytes_per_window // 1024

        if total_kb > max_kb:
            severity = min((total_kb / max(max_kb, 1) - 1.0) * 0.4 + 0.5, 1.0)
            issues.append(
                f"Data volume exceeded: ~{total_kb}KB/{max_kb}KB per window"
            )
            max_severity = max(max_severity, severity)

        if not issues:
            return DefenseResult(action="pass", confidence=1.0)

        composite = min(max_severity, 1.0)
        if composite >= 0.80:
            action = "block"
        elif composite >= 0.45:
            action = "flag"
        else:
            action = "pass"

        reason = "; ".join(issues) + f" (score={composite:.2f})"

        if action != "pass":
            logger.info(
                "RateLimiter triggered",
                extra={
                    "extra_data": {
                        "action": action,
                        "session_id": session_id,
                        "score": round(composite, 4),
                        "issues": issues,
                    }
                },
            )

        return DefenseResult(action=action, reason=reason, confidence=composite)

    def get_rules(self) -> list[DetectionRule]:
        return [
            DetectionRule(
                name="request_rate_limit",
                pattern=f">{self.max_requests_per_window} requests/{self.window_seconds}s",
                description="Maximum request rate per sliding window",
                severity="high",
            ),
            DetectionRule(
                name="tool_call_rate_limit",
                pattern=f">{self.max_tool_calls_per_window} tool_calls/{self.window_seconds}s",
                description="Maximum tool call rate per sliding window",
                severity="high",
            ),
            DetectionRule(
                name="data_volume_limit",
                pattern=f">{self.max_data_bytes_per_window} bytes/{self.window_seconds}s",
                description="Maximum data volume per sliding window",
                severity="medium",
            ),
            DetectionRule(
                name="burst_detection",
                pattern=f">{self.burst_factor}x expected rate in 5s",
                description="Short-term burst detection within 5-second micro-window",
                severity="high",
            ),
        ]
