"""Network-specific consensus parameters and script verification flags."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntFlag
from types import MappingProxyType
from typing import Final, Mapping

from src.core.network_profiles import NetworkName

__all__ = [
    "CHAIN_PARAMS",
    "ChainParams",
    "MAINNET_CHAIN_PARAMS",
    "REGTEST_CHAIN_PARAMS",
    "SIGNET_CHAIN_PARAMS",
    "ScriptVerifyFlag",
    "TESTNET_CHAIN_PARAMS",
    "get_chain_params",
]


class ScriptVerifyFlag(IntFlag):
    """Consensus and policy script checks selected for a candidate block."""

    NONE = 0
    P2SH = 1 << 0
    DERSIG = 1 << 1
    CHECKLOCKTIMEVERIFY = 1 << 2
    WITNESS = 1 << 3
    TAPROOT = 1 << 4

    # Relay/mempool policy flags. They are not block-consensus rules.
    STRICTENC = 1 << 8
    MINIMALDATA = 1 << 9
    NULLDUMMY = 1 << 10
    CLEANSTACK = 1 << 11


STANDARD_POLICY_FLAGS: Final = (
    ScriptVerifyFlag.STRICTENC
    | ScriptVerifyFlag.MINIMALDATA
    | ScriptVerifyFlag.NULLDUMMY
    | ScriptVerifyFlag.CLEANSTACK
)


def _internal_hash(display_hash: str) -> bytes:
    """Convert the conventional displayed block hash to wire/internal byte order."""
    return bytes.fromhex(display_hash)[::-1]


@dataclass(frozen=True, slots=True)
class ChainParams:
    """Immutable consensus parameters for one Bitcoin network."""

    network: NetworkName
    genesis_hash: bytes
    bip16_activation_time: int
    bip34_height: int
    bip65_height: int
    bip66_height: int
    segwit_height: int
    taproot_height: int
    script_flag_exceptions: Mapping[bytes, ScriptVerifyFlag]
    bip30_exceptions: Mapping[int, bytes]

    def consensus_script_flags(
            self,
            height: int,
            *,
            block_time: int | None = None,
            block_hash: bytes | None = None,
    ) -> ScriptVerifyFlag:
        """Return the consensus script flags for a block on this network."""
        if block_hash is not None and block_hash in self.script_flag_exceptions:
            return self.script_flag_exceptions[block_hash]

        flags = ScriptVerifyFlag.NONE
        if block_time is None or block_time >= self.bip16_activation_time:
            flags |= ScriptVerifyFlag.P2SH
        if height >= self.bip66_height:
            flags |= ScriptVerifyFlag.DERSIG
        if height >= self.bip65_height:
            flags |= ScriptVerifyFlag.CHECKLOCKTIMEVERIFY
        if height >= self.segwit_height:
            flags |= ScriptVerifyFlag.WITNESS
        if height >= self.taproot_height:
            flags |= ScriptVerifyFlag.TAPROOT
        return flags

    def standard_script_flags(
            self,
            height: int,
            *,
            block_time: int | None = None,
            block_hash: bytes | None = None,
    ) -> ScriptVerifyFlag:
        """Return policy flags layered on the active consensus flags."""
        return self.consensus_script_flags(
            height,
            block_time=block_time,
            block_hash=block_hash,
        ) | STANDARD_POLICY_FLAGS

    def is_bip30_exception(self, height: int, block_hash: bytes) -> bool:
        """Return whether this is one of Bitcoin's two historical BIP30 blocks."""
        return self.bip30_exceptions.get(height) == block_hash


_MAINNET_BIP16_EXCEPTION = _internal_hash(
    "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
)
_MAINNET_TAPROOT_EXCEPTION = _internal_hash(
    "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"
)
_TESTNET_BIP16_EXCEPTION = _internal_hash(
    "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"
)

MAINNET_CHAIN_PARAMS: Final = ChainParams(
    network=NetworkName.MAINNET,
    genesis_hash=_internal_hash(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    ),
    bip16_activation_time=1_333_238_400,
    bip34_height=227_931,
    bip65_height=388_381,
    bip66_height=363_725,
    segwit_height=481_824,
    taproot_height=709_632,
    script_flag_exceptions=MappingProxyType({
        _MAINNET_BIP16_EXCEPTION: ScriptVerifyFlag.NONE,
        _MAINNET_TAPROOT_EXCEPTION: ScriptVerifyFlag.P2SH | ScriptVerifyFlag.WITNESS,
    }),
    bip30_exceptions=MappingProxyType({
        91_842: _internal_hash(
            "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"
        ),
        91_880: _internal_hash(
            "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"
        ),
    }),
)

TESTNET_CHAIN_PARAMS: Final = ChainParams(
    network=NetworkName.TESTNET,
    genesis_hash=_internal_hash(
        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
    ),
    bip16_activation_time=1_333_238_400,
    bip34_height=21_111,
    bip65_height=581_885,
    bip66_height=330_776,
    segwit_height=834_624,
    taproot_height=2_011_968,
    script_flag_exceptions=MappingProxyType({
        _TESTNET_BIP16_EXCEPTION: ScriptVerifyFlag.NONE,
    }),
    bip30_exceptions=MappingProxyType({}),
)

REGTEST_CHAIN_PARAMS: Final = ChainParams(
    network=NetworkName.REGTEST,
    genesis_hash=_internal_hash(
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    ),
    bip16_activation_time=0,
    bip34_height=1,
    bip65_height=1,
    bip66_height=1,
    segwit_height=0,
    taproot_height=0,
    script_flag_exceptions=MappingProxyType({}),
    bip30_exceptions=MappingProxyType({}),
)

SIGNET_CHAIN_PARAMS: Final = ChainParams(
    network=NetworkName.SIGNET,
    genesis_hash=_internal_hash(
        "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
    ),
    bip16_activation_time=0,
    bip34_height=1,
    bip65_height=1,
    bip66_height=1,
    segwit_height=1,
    taproot_height=0,
    script_flag_exceptions=MappingProxyType({}),
    bip30_exceptions=MappingProxyType({}),
)

CHAIN_PARAMS: Final = MappingProxyType({
    params.network: params
    for params in (
        MAINNET_CHAIN_PARAMS,
        TESTNET_CHAIN_PARAMS,
        REGTEST_CHAIN_PARAMS,
        SIGNET_CHAIN_PARAMS,
    )
})


def get_chain_params(network: NetworkName | str) -> ChainParams:
    """Return the canonical consensus parameters for a supported network."""
    name = network if isinstance(network, NetworkName) else NetworkName(network)
    return CHAIN_PARAMS[name]
