# src/data/netparams.py
from dataclasses import dataclass
from typing import Tuple

__all__ = ["NetworkParams", "MAINNET", "TESTNET", "SIGNET", "REGTEST"]


@dataclass(frozen=True, slots=True)
class NetworkParams:
    """Immutable network parameters."""
    magic: bytes
    default_port: int
    dns_seeds: Tuple[str, ...] = ()


MAINNET = NetworkParams(
    magic=b"\xf9\xbe\xb4\xd9", default_port=8333,
    dns_seeds=(
        "seed.bitcoin.sipa.be",
        "dnsseed.bluematt.me",
        "seed.bitcoinstats.com",
        "seed.bitcoin.jonasschnelli.ch",
        "seed.btc.petertodd.org",
    ),
)

TESTNET = NetworkParams(
    magic=b"\x0b\x11\x09\x07", default_port=18333,
    dns_seeds=("testnet-seed.bitcoin.jonasschnelli.ch", "seed.tbtc.petertodd.org"),
)

SIGNET = NetworkParams(
    magic=b"\x0a\x0a\x0a\x0a", default_port=38333,
    dns_seeds=("seed.signet.bitcoin.sprovoost.nl",),
)

REGTEST = NetworkParams(
    magic=b"\xfa\xbf\xb5\xda", default_port=18444, dns_seeds=(),
)
