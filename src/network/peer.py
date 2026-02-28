"""
The Peer class, used to track information about remote nodes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from time import time
from typing import Optional

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
    protocol_version: Optional[int] = None
    services: Optional[Services] = None
    user_agent: Optional[str] = None
    nonce: Optional[int] = None
    last_block: Optional[int] = None

    # --- Bookkeeping
    last_seen: float = field(default_factory=time)
    last_success: Optional[float] = None
    last_fail: Optional[float] = None
    fail_count: int = 0

    @property
    def key(self) -> tuple[str, int]:
        return str(self.host), int(self.port)
