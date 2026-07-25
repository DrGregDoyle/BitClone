"""Peer misbehaviour scoring and temporary bans."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import Enum
from ipaddress import ip_address
from typing import Callable

__all__ = [
    "DEFAULT_BAN_DURATION",
    "DEFAULT_BAN_THRESHOLD",
    "PeerBan",
    "PeerDiscipline",
    "PeerMisbehaviour",
]

DEFAULT_BAN_THRESHOLD = 100
DEFAULT_BAN_DURATION = 24 * 60 * 60


class PeerMisbehaviour(Enum):
    """Reviewed violation categories and their score increments."""

    MALFORMED_MESSAGE = ("malformed-message", 20)
    PROTOCOL_VIOLATION = ("protocol-violation", 20)
    INVALID_DATA = ("invalid-data", 50)

    def __init__(self, label: str, score: int):
        self.label = label
        self.score = score


@dataclass(frozen=True, slots=True)
class PeerBan:
    host: str
    score: int
    reason: str
    banned_until: float


class PeerDiscipline:
    """Accumulate host-level scores and expire temporary bans."""

    def __init__(
            self,
            ban_threshold: int = DEFAULT_BAN_THRESHOLD,
            ban_duration: float = DEFAULT_BAN_DURATION,
            clock: Callable[[], float] = time.monotonic,
    ):
        if ban_threshold <= 0:
            raise ValueError("Ban threshold must be positive")
        if ban_duration <= 0:
            raise ValueError("Ban duration must be positive")
        self.ban_threshold = int(ban_threshold)
        self.ban_duration = float(ban_duration)
        self._clock = clock
        self._scores: dict[str, int] = {}
        self._bans: dict[str, PeerBan] = {}
        self._lock = threading.RLock()

    def record(self, host: str, violation: PeerMisbehaviour) -> int:
        """Apply one violation and return the host's new score."""
        normalized = self._normalize_host(host)
        with self._lock:
            self._expire(normalized)
            score = self._scores.get(normalized, 0) + violation.score
            self._scores[normalized] = score
            if score >= self.ban_threshold:
                self._bans[normalized] = PeerBan(
                    host=normalized,
                    score=score,
                    reason=violation.label,
                    banned_until=self._clock() + self.ban_duration,
                )
            return score

    def score(self, host: str) -> int:
        normalized = self._normalize_host(host)
        with self._lock:
            self._expire(normalized)
            return self._scores.get(normalized, 0)

    def is_banned(self, host: str) -> bool:
        normalized = self._normalize_host(host)
        with self._lock:
            self._expire(normalized)
            return normalized in self._bans

    def ban(self, host: str) -> PeerBan | None:
        normalized = self._normalize_host(host)
        with self._lock:
            self._expire(normalized)
            return self._bans.get(normalized)

    def active_bans(self) -> tuple[PeerBan, ...]:
        with self._lock:
            for host in tuple(self._bans):
                self._expire(host)
            return tuple(self._bans[host] for host in sorted(self._bans))

    def _expire(self, host: str) -> None:
        ban = self._bans.get(host)
        if ban is not None and ban.banned_until <= self._clock():
            self._bans.pop(host, None)
            self._scores.pop(host, None)

    @staticmethod
    def _normalize_host(host: str) -> str:
        text = str(host)
        try:
            return str(ip_address(text))
        except ValueError:
            return text.rstrip(".").lower()
