"""Resolve Bitcoin Core DNS seeds into BitClone's peer address book."""

from __future__ import annotations

import json
import socket
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final

from src.core.network_profiles import NETWORK_PROFILES, NetworkName
from src.network.peer_address_book import PeerAddressBook, PeerKey, PeerSource

__all__ = [
    "BITCOIN_CORE_CHAINPARAMS_SOURCE",
    "BITCOIN_CORE_SEED_VERSION",
    "DNS_SEEDS",
    "DNSResolver",
    "DNSSeedBootstrap",
    "DNSSeedFailure",
    "DNSSeedResult",
    "DEFAULT_DNS_SEED_WORKERS",
]

BITCOIN_CORE_SEED_VERSION: Final[str] = "v31.0"
BITCOIN_CORE_CHAINPARAMS_SOURCE: Final[str] = (
    "https://github.com/bitcoin/bitcoin/blob/v31.0/src/kernel/chainparams.cpp"
)

DNS_SEEDS = MappingProxyType({
    network: profile.dns_seeds for network, profile in NETWORK_PROFILES.items()
})
DEFAULT_DNS_SEED_WORKERS: Final[int] = 4

AddressInfo = tuple[int, int, int, str, tuple[Any, ...]]
DNSResolver = Callable[[str, int], Iterable[AddressInfo]]


def _system_resolver(host: str, port: int) -> Iterable[AddressInfo]:
    return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)


@dataclass(frozen=True, slots=True)
class DNSSeedFailure:
    seed: str
    error: str

    def to_data(self) -> dict[str, str]:
        return {"seed": self.seed, "error": self.error}


@dataclass(frozen=True, slots=True)
class DNSSeedResult:
    network: NetworkName
    port: int
    queried_seeds: tuple[str, ...]
    peer_keys: tuple[PeerKey, ...]
    failures: tuple[DNSSeedFailure, ...]

    @property
    def resolved_count(self) -> int:
        return len(self.peer_keys)

    def to_data(self) -> dict[str, Any]:
        return {
            "network": self.network.value,
            "port": self.port,
            "queried_seeds": list(self.queried_seeds),
            "resolved_count": self.resolved_count,
            "peers": [list(peer_key) for peer_key in self.peer_keys],
            "failures": [failure.to_data() for failure in self.failures],
        }

    def to_display(self) -> str:
        return json.dumps(self.to_data(), indent=2)


class DNSSeedBootstrap:
    """Query the seeds for one network and merge their results into an address book."""

    def __init__(
            self,
            network: NetworkName | str,
            address_book: PeerAddressBook,
            port: int | None = None,
            resolver: DNSResolver | None = None,
            max_workers: int = DEFAULT_DNS_SEED_WORKERS,
    ):
        self.network = network if isinstance(network, NetworkName) else NetworkName(network)
        self.address_book = address_book
        self.port = address_book.default_port if port is None else port
        self.resolver = _system_resolver if resolver is None else resolver
        if not isinstance(max_workers, int) or isinstance(max_workers, bool) or max_workers < 1:
            raise ValueError("DNS seed worker count must be a positive integer")
        self.max_workers = max_workers

    def resolve(self) -> DNSSeedResult:
        queried_seeds = DNS_SEEDS[self.network]
        failures: list[DNSSeedFailure] = []
        peer_keys: set[PeerKey] = set()

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            seed_results = executor.map(self._resolve_seed, queried_seeds)
            for seed, addresses, error in seed_results:
                if error is not None:
                    failures.append(DNSSeedFailure(seed, str(error)))
                    continue
                for family, socket_address in addresses:
                    if family not in (socket.AF_INET, socket.AF_INET6):
                        continue
                    peer = self.address_book.add(
                        socket_address[0],
                        self.port,
                        source=PeerSource.DNS_SEED,
                    )
                    peer_keys.add(peer.key)

        return DNSSeedResult(
            network=self.network,
            port=self.port,
            queried_seeds=queried_seeds,
            peer_keys=tuple(sorted(peer_keys)),
            failures=tuple(failures),
        )

    def _resolve_seed(
            self,
            seed: str,
    ) -> tuple[str, tuple[tuple[int, tuple[Any, ...]], ...], OSError | None]:
        """Resolve one seed without mutating shared bootstrap state."""
        try:
            addresses = tuple(
                (family, socket_address)
                for family, _socktype, _protocol, _canonical_name, socket_address
                in self.resolver(seed, self.port)
            )
            return seed, addresses, None
        except OSError as error:
            return seed, (), error
