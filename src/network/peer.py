"""
The Peer class, used to track information about remote nodes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from time import time

from src.data.ip_utils import IP_ADDRESS
from src.network.datatypes.network_types import PeerState, Services

__all__ = ["Peer"]


@dataclass
class Peer:
    """Represents a remote node and what we know about it."""
    host: str | IP_ADDRESS
    port: int

    state: PeerState = field(default=PeerState.DISCONNECTED)

    # --- Learned/negotiated via handshake
    protocol_version: int | None = None
    services: Services | None = None
    user_agent: str | None = None
    nonce: int | None = None
    local_nonce: int | None = None
    last_block: int | None = None

    # --- Bookkeeping
    last_seen: float = field(default_factory=time)
    last_success: float | None = None
    last_fail: float | None = None
    fail_count: int = 0

    @property
    def key(self) -> tuple[str, int]:
        return str(self.host), int(self.port)

    def transition(self, state: PeerState, observed_at: float | None = None) -> None:
        """Apply a peer session state transition in one place."""
        self.state = state
        if observed_at is not None:
            self.note_activity(observed_at)

    def note_activity(self, observed_at: float | None = None) -> None:
        timestamp = time() if observed_at is None else observed_at
        self.last_seen = max(self.last_seen, timestamp)

    def record_success(self, succeeded_at: float | None = None) -> None:
        timestamp = time() if succeeded_at is None else succeeded_at
        self.last_success = timestamp
        self.note_activity(timestamp)

    def record_failure(self, failed_at: float | None = None) -> None:
        timestamp = time() if failed_at is None else failed_at
        self.last_fail = timestamp
        self.fail_count += 1
        self.transition(PeerState.DISCONNECTED, timestamp)
