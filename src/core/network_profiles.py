"""Immutable parameters that identify each supported Bitcoin network."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final

__all__ = [
    "MAINNET_PROFILE",
    "NETWORK_PROFILES",
    "NetworkName",
    "NetworkProfile",
    "REGTEST_PROFILE",
    "SIGNET_PROFILE",
    "TESTNET_PROFILE",
    "get_network_profile",
]


class NetworkName(str, Enum):
    MAINNET = "mainnet"
    TESTNET = "testnet"
    REGTEST = "regtest"
    SIGNET = "signet"


@dataclass(frozen=True, slots=True)
class NetworkProfile:
    name: NetworkName
    magic_bytes: bytes
    p2p_port: int
    dns_seeds: tuple[str, ...]


MAINNET_PROFILE: Final = NetworkProfile(
    name=NetworkName.MAINNET,
    magic_bytes=b"\xf9\xbe\xb4\xd9",
    p2p_port=8333,
    dns_seeds=(
        "seed.bitcoin.sipa.be.",
        "dnsseed.bluematt.me.",
        "seed.bitcoin.jonasschnelli.ch.",
        "seed.btc.petertodd.net.",
        "seed.bitcoin.sprovoost.nl.",
        "dnsseed.emzy.de.",
        "seed.bitcoin.wiz.biz.",
        "seed.mainnet.achownodes.xyz.",
    ),
)
TESTNET_PROFILE: Final = NetworkProfile(
    name=NetworkName.TESTNET,
    magic_bytes=b"\x0b\x11\x09\x07",
    p2p_port=18333,
    dns_seeds=(
        "testnet-seed.bitcoin.jonasschnelli.ch.",
        "seed.tbtc.petertodd.net.",
        "seed.testnet.bitcoin.sprovoost.nl.",
        "testnet-seed.bluematt.me.",
        "seed.testnet.achownodes.xyz.",
    ),
)
REGTEST_PROFILE: Final = NetworkProfile(
    name=NetworkName.REGTEST,
    magic_bytes=b"\xfa\xbf\xb5\xda",
    p2p_port=18444,
    dns_seeds=(),
)
SIGNET_PROFILE: Final = NetworkProfile(
    name=NetworkName.SIGNET,
    magic_bytes=b"\x0a\x03\xcf\x40",
    p2p_port=38333,
    dns_seeds=(
        "seed.signet.bitcoin.sprovoost.nl.",
        "seed.signet.achownodes.xyz.",
    ),
)

NETWORK_PROFILES = MappingProxyType({
    profile.name: profile
    for profile in (
        MAINNET_PROFILE,
        TESTNET_PROFILE,
        REGTEST_PROFILE,
        SIGNET_PROFILE,
    )
})


def get_network_profile(network: NetworkName | str) -> NetworkProfile:
    """Return the canonical immutable profile for a supported network."""
    name = network if isinstance(network, NetworkName) else NetworkName(network)
    return NETWORK_PROFILES[name]
