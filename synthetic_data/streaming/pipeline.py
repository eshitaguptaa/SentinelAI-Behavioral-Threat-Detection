"""Streaming-feasibility adapter for near-real-time scoring.

Production deployments can feed events from Kafka / Redis Streams / cloud
pubsub into ``StreamingScorer.on_event``. This module demonstrates the contract
without requiring a broker — scores reuse the same batch inference pipeline
once a session window closes or a flush interval elapses.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from synthetic_data.generators.event_factory import TimelineEvent


@dataclass
class StreamingScorer:
    """Buffers per-entity events and flushes windows to a scoring callback.

    Args:
        score_fn: Callable receiving a list of ``TimelineEvent`` for one
            entity window and returning an arbitrary result payload.
        max_buffer: Soft cap on buffered events per entity.
        flush_every: Auto-flush after this many events for an entity.
    """

    score_fn: Callable[[list[TimelineEvent]], Any]
    max_buffer: int = 500
    flush_every: int = 32
    _buffers: dict[str, deque[TimelineEvent]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    _results: list[Any] = field(default_factory=list)

    def on_event(self, event: TimelineEvent) -> Any | None:
        """Ingest one event; return a score result when a window flushes."""
        buf = self._buffers[event.employee_id]
        buf.append(event)
        while len(buf) > self.max_buffer:
            buf.popleft()
        if len(buf) >= self.flush_every:
            return self.flush(event.employee_id)
        return None

    def on_events(self, events: Iterable[TimelineEvent]) -> list[Any]:
        """Ingest a batch; return any flush results produced along the way."""
        outputs: list[Any] = []
        for event in events:
            result = self.on_event(event)
            if result is not None:
                outputs.append(result)
        return outputs

    def flush(self, entity_id: str) -> Any | None:
        """Score and clear the buffer for one entity."""
        buf = self._buffers.get(entity_id)
        if not buf:
            return None
        window = list(buf)
        buf.clear()
        result = self.score_fn(window)
        self._results.append(result)
        return result

    def flush_all(self) -> list[Any]:
        """Flush every non-empty entity buffer."""
        outputs: list[Any] = []
        for entity_id in list(self._buffers.keys()):
            result = self.flush(entity_id)
            if result is not None:
                outputs.append(result)
        return outputs


def demo_wall_clock_key(ts: datetime) -> str:
    """Bucket helper for minute-level streaming windows."""
    return ts.strftime("%Y-%m-%dT%H:%M")
