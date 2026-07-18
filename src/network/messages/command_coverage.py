"""Reviewed comparison between BitClone and Bitcoin Core P2P commands.

This inventory is a maintenance aid only. It must not be used as a framing
allowlist: valid messages with unsupported commands remain forward-compatible
and are represented by ``UnknownMessage``.
"""

from dataclasses import dataclass

from src.network.messages.message import Message


BITCOIN_CORE_VERSION = "v31.0"
BITCOIN_CORE_PROTOCOL_SOURCE = (
    "https://github.com/bitcoin/bitcoin/blob/v31.0/src/protocol.h"
)

# Bitcoin Core v31.0, protocol.h: NetMsgType::ALL_NET_MESSAGE_TYPES.
BITCOIN_CORE_COMMANDS = frozenset({
    "version",
    "verack",
    "addr",
    "addrv2",
    "sendaddrv2",
    "inv",
    "getdata",
    "merkleblock",
    "getblocks",
    "getheaders",
    "tx",
    "headers",
    "block",
    "getaddr",
    "mempool",
    "ping",
    "pong",
    "notfound",
    "filterload",
    "filteradd",
    "filterclear",
    "sendheaders",
    "feefilter",
    "sendcmpct",
    "cmpctblock",
    "getblocktxn",
    "blocktxn",
    "getcfilters",
    "cfilter",
    "getcfheaders",
    "cfheaders",
    "getcfcheckpt",
    "cfcheckpt",
    "wtxidrelay",
    "sendtxrcncl",
})

# Commands known to have reached Bitcoin Core after the pinned target. Keeping
# these separate prevents a moving development branch from changing the audit.
KNOWN_POST_TARGET_COMMANDS = frozenset({"feature"})


@dataclass(frozen=True)
class CommandCoverage:
    """Immutable command-coverage result for the pinned Bitcoin Core target."""

    implemented: frozenset[str]
    implemented_upstream: frozenset[str]
    missing_upstream: frozenset[str]
    local_only: frozenset[str]


def get_command_coverage() -> CommandCoverage:
    """Compare imported BitClone commands with the reviewed Core snapshot."""
    implemented = Message.registered_commands()
    return CommandCoverage(
        implemented=implemented,
        implemented_upstream=implemented & BITCOIN_CORE_COMMANDS,
        missing_upstream=BITCOIN_CORE_COMMANDS - implemented,
        local_only=implemented - BITCOIN_CORE_COMMANDS,
    )
