"""Known Bitcoin peer addresses and connection metadata."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Iterable

from src.core import NETWORK
from src.network.datatypes.network_data import NetAddr
from src.network.datatypes.network_types import Services
from src.network.peer import Peer

__all__ = ["PeerAddress", "PeerAddressBook", "PeerKey", "PeerSource"]

IPAddress = IPv4Address | IPv6Address
PeerKey = tuple[str, int]


class PeerSource(str, Enum):
    """How BitClone learned about a peer address."""

    MANUAL = "manual"
    DNS_SEED = "dns_seed"
    ADDR = "addr"


@dataclass(slots=True)
class PeerAddress:
    """A deduplicated peer endpoint and everything learned about it."""

    host: IPAddress
    port: int
    sources: set[PeerSource] = field(default_factory=set)
    services: Services = Services.UNNAMED
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    last_success: float | None = None
    last_failure: float | None = None
    success_count: int = 0
    fail_count: int = 0
    protocol_version: int | None = None
    user_agent: str | None = None
    last_block: int | None = None

    @property
    def key(self) -> PeerKey:
        return str(self.host), self.port

    def to_data(self) -> dict:
        return {
            "host": str(self.host),
            "port": self.port,
            "sources": sorted(source.value for source in self.sources),
            "services": int(self.services),
            "service_names": self.services.name,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "last_success": self.last_success,
            "last_failure": self.last_failure,
            "success_count": self.success_count,
            "fail_count": self.fail_count,
            "protocol_version": self.protocol_version,
            "user_agent": self.user_agent,
            "last_block": self.last_block,
        }


class PeerAddressBook:
    """In-memory store of known, deduplicated Bitcoin peer endpoints."""

    def __init__(self, default_port: int = NETWORK.MAINNET_PORT):
        self.default_port = self._validate_port(default_port)
        self._entries: dict[PeerKey, PeerAddress] = {}

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self._entries.values())

    def add(
            self,
            host: str | IPAddress,
            port: int | None = None,
            source: PeerSource = PeerSource.MANUAL,
            services: Services = Services.UNNAMED,
            seen_at: float | None = None,
    ) -> PeerAddress:
        normalized_host = ip_address(str(host))
        normalized_port = self._validate_port(self.default_port if port is None else port)
        observed_at = time.time() if seen_at is None else seen_at
        key = str(normalized_host), normalized_port
        entry = self._entries.get(key)

        if entry is None:
            entry = PeerAddress(
                host=normalized_host,
                port=normalized_port,
                sources={source},
                services=Services(services),
                first_seen=observed_at,
                last_seen=observed_at,
            )
            self._entries[key] = entry
        else:
            entry.sources.add(source)
            entry.services |= Services(services)
            entry.last_seen = max(entry.last_seen, observed_at)

        return entry

    def add_peer(
            self,
            peer: Peer,
            source: PeerSource = PeerSource.MANUAL,
            seen_at: float | None = None,
    ) -> PeerAddress:
        entry = self.add(
            peer.host,
            peer.port,
            source=source,
            services=peer.services or Services.UNNAMED,
            seen_at=peer.last_seen if seen_at is None else seen_at,
        )
        if peer.protocol_version is not None:
            entry.protocol_version = peer.protocol_version
        if peer.user_agent is not None:
            entry.user_agent = peer.user_agent
        if peer.last_block is not None:
            entry.last_block = peer.last_block
        return entry

    def merge_net_addresses(self, addresses: Iterable[NetAddr]) -> tuple[PeerAddress, ...]:
        """Merge addresses learned from an ``addr`` message."""
        merged: dict[PeerKey, PeerAddress] = {}
        for address in addresses:
            try:
                entry = self.add(
                    address.ip_addr.ip,
                    address.port,
                    source=PeerSource.ADDR,
                    services=address.services,
                    seen_at=float(address.timestamp),
                )
            except ValueError:
                # Valid wire addresses can still be unusable connection targets,
                # for example when they advertise port zero.
                continue
            merged[entry.key] = entry
        return tuple(merged[key] for key in sorted(merged))

    def get(self, host: str | IPAddress, port: int | None = None) -> PeerAddress | None:
        normalized_host = ip_address(str(host))
        normalized_port = self.default_port if port is None else self._validate_port(port)
        return self._entries.get((str(normalized_host), normalized_port))

    def record_success(
            self,
            peer: Peer,
            source: PeerSource = PeerSource.MANUAL,
            succeeded_at: float | None = None,
    ) -> PeerAddress:
        timestamp = time.time() if succeeded_at is None else succeeded_at
        peer.record_success(timestamp)
        entry = self.add_peer(peer, source=source, seen_at=timestamp)
        entry.last_success = timestamp
        entry.success_count += 1
        return entry

    def record_failure(
            self,
            peer: Peer,
            source: PeerSource = PeerSource.MANUAL,
            failed_at: float | None = None,
    ) -> PeerAddress:
        timestamp = time.time() if failed_at is None else failed_at
        peer.record_failure(timestamp)
        entry = self.add_peer(peer, source=source, seen_at=timestamp)
        entry.last_failure = timestamp
        entry.fail_count += 1
        return entry

    def candidates(
            self,
            limit: int | None = None,
            exclude: Iterable[PeerKey] = (),
    ) -> tuple[PeerAddress, ...]:
        """Return deterministic candidates, preferring reliable and recent peers."""
        excluded = set(exclude)
        entries = (entry for entry in self._entries.values() if entry.key not in excluded)
        ordered = sorted(
            entries,
            key=lambda entry: (
                entry.fail_count,
                -(entry.last_success or 0),
                -entry.last_seen,
                entry.key,
            ),
        )
        if limit is not None:
            if limit < 0:
                raise ValueError("Candidate limit cannot be negative")
            ordered = ordered[:limit]
        return tuple(ordered)

    def to_data(self) -> dict:
        peers = sorted(self._entries.values(), key=lambda entry: entry.key)
        return {
            "count": len(peers),
            "default_port": self.default_port,
            "peers": [peer.to_data() for peer in peers],
        }

    def to_display(self) -> str:
        return json.dumps(self.to_data(), indent=2)

    @staticmethod
    def _validate_port(port: int) -> int:
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65_535:
            raise ValueError(f"Invalid peer port: {port!r}")
        return port
