"""Bounded event publication and node-state monitoring for SSE clients."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import json
import threading
import time
from typing import Any, Callable, Iterator

from src.api.security import redact_secrets


EVENT_TYPES = frozenset({"sync", "peer", "block", "mempool", "warning", "lifecycle"})


@dataclass(frozen=True, slots=True)
class NodeEvent:
    event_id: int
    event_type: str
    data: dict[str, Any]

    def to_sse(self) -> bytes:
        payload = json.dumps(
            redact_secrets(self.data),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
        return (
            f"id: {self.event_id}\n"
            f"event: {self.event_type}\n"
            f"data: {payload}\n\n"
        ).encode("utf-8")


class EventHub:
    """Thread-safe bounded event history with resumable subscriptions."""

    def __init__(self, history_size: int = 512):
        if history_size < 1:
            raise ValueError("Event history size must be positive")
        self._events: deque[NodeEvent] = deque(maxlen=history_size)
        self._next_id = 1
        self._closed = False
        self._condition = threading.Condition()

    def publish(self, event_type: str, data: dict[str, Any]) -> NodeEvent:
        if event_type not in EVENT_TYPES:
            raise ValueError(f"Unsupported event type: {event_type}")
        with self._condition:
            event = NodeEvent(self._next_id, event_type, redact_secrets(data))
            self._next_id += 1
            self._events.append(event)
            self._condition.notify_all()
            return event

    def subscribe(
            self,
            last_event_id: int = 0,
            heartbeat_seconds: float = 15.0,
    ) -> Iterator[NodeEvent | None]:
        cursor = last_event_id
        while True:
            with self._condition:
                available = [event for event in self._events if event.event_id > cursor]
                if not available and not self._closed:
                    self._condition.wait(timeout=heartbeat_seconds)
                    available = [event for event in self._events if event.event_id > cursor]
                if self._closed:
                    return
            if not available:
                yield None
                continue
            for event in available:
                cursor = event.event_id
                yield event

    def close(self) -> None:
        with self._condition:
            self._closed = True
            self._condition.notify_all()


class NodeEventMonitor:
    """Publish changes from bounded, in-memory node snapshots."""

    def __init__(
            self,
            snapshot: Callable[[], dict[str, dict[str, Any]]],
            events: EventHub,
            interval: float = 1.0,
    ):
        self.snapshot = snapshot
        self.events = events
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="bitclone-api-events",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(1.0, self.interval * 2))
        self._thread = None

    def _run(self) -> None:
        previous: dict[str, dict[str, Any]] = {}
        while not self._stop.is_set():
            try:
                current = self.snapshot()
                for event_type, data in current.items():
                    if previous.get(event_type) != data:
                        self.events.publish(event_type, data)
                previous = current
            except Exception as error:
                self.events.publish(
                    "warning",
                    {
                        "code": "event_monitor_failure",
                        "message": "The node event monitor could not read its current snapshot.",
                        "error_type": type(error).__name__,
                    },
                )
            self._stop.wait(self.interval)
