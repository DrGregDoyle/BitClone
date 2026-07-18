"""Resolve Bitcoin Core DNS seeds into BitClone's peer address book."""

from __future__ import annotations

import json
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final

from src.config import NetworkName
from src.core import NETWORK
from src.network.peer_address_book import PeerAddressBook, PeerKey, PeerSource

__all__ = [
    "BITCOIN_CORE_CHAINPARAMS_SOURCE",
    "BITCOIN_CORE_SEED_VERSION",
    "DNS_SEEDS",
    "DNSResolver",
    "DNSSeedBootstrap",
    "DNSSeedFailure",
    "DNSSeedResult",
]

BITCOIN_CORE_SEED_VERSION: Final[str] = "v31.0"
BITCOIN_CORE_CHAINPARAMS_SOURCE: Final[str] = (
    "https://github.com/bitcoin/bitcoin/blob/v31.0/src/kernel/chainparams.cpp"
)

DNS_SEEDS = MappingProxyType({
    NetworkName.MAINNET: NETWORK.MAINNET_DNS_SEEDS,
    NetworkName.TESTNET: NETWORK.TESTNET_DNS_SEEDS,
    NetworkName.SIGNET: NETWORK.SIGNET_DNS_SEEDS,
    NetworkName.REGTEST: NETWORK.REGTEST_DNS_SEEDS,
})

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
    ):
        self.network = network if isinstance(network, NetworkName) else NetworkName(network)
        self.address_book = address_book
        self.port = address_book.default_port if port is None else port
        self.resolver = _system_resolver if resolver is None else resolver

    def resolve(self) -> DNSSeedResult:
        queried_seeds: list[str] = []
        failures: list[DNSSeedFailure] = []
        peer_keys: set[PeerKey] = set()

        for seed in DNS_SEEDS[self.network]:
            queried_seeds.append(seed)
            try:
                for family, _socktype, _protocol, _canonical_name, socket_address in self.resolver(
                        seed, self.port
                ):
                    if family not in (socket.AF_INET, socket.AF_INET6):
                        continue
                    peer = self.address_book.add(
                        socket_address[0],
                        self.port,
                        source=PeerSource.DNS_SEED,
                    )
                    peer_keys.add(peer.key)
            except OSError as error:
                failures.append(DNSSeedFailure(seed, str(error)))
                continue

        return DNSSeedResult(
            network=self.network,
            port=self.port,
            queried_seeds=tuple(queried_seeds),
            peer_keys=tuple(sorted(peer_keys)),
            failures=tuple(failures),
        )
