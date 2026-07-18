import pytest

from src.core import MAGICBYTES
from src.network.messages import Message
from src.network.messages.command_coverage import (
    BITCOIN_CORE_COMMANDS,
    BITCOIN_CORE_PROTOCOL_SOURCE,
    BITCOIN_CORE_VERSION,
    KNOWN_POST_TARGET_COMMANDS,
    get_command_coverage,
)
from src.network.messages.message import UnknownMessage


def test_builtin_message_modules_are_registered_deterministically():
    commands = Message.registered_commands()

    assert isinstance(commands, frozenset)
    assert {"version", "block", "cfilter"} <= commands

    with pytest.raises(AttributeError):
        commands.add("futuremsg")


def test_command_coverage_matches_reviewed_bitcoin_core_snapshot():
    coverage = get_command_coverage()

    assert BITCOIN_CORE_VERSION == "v31.0"
    assert BITCOIN_CORE_PROTOCOL_SOURCE.endswith("/v31.0/src/protocol.h")
    assert coverage.implemented_upstream == BITCOIN_CORE_COMMANDS - {
        "addrv2",
        "sendtxrcncl",
    }
    assert coverage.missing_upstream == frozenset({"addrv2", "sendtxrcncl"})
    assert coverage.local_only == frozenset({"reject"})
    assert KNOWN_POST_TARGET_COMMANDS == frozenset({"feature"})


def test_valid_unsupported_command_remains_an_unknown_message():
    message = UnknownMessage("feature", b"future payload", MAGICBYTES.MAINNET)
    parsed = UnknownMessage.from_bytes(message.to_bytes())

    assert "feature" not in BITCOIN_CORE_COMMANDS
    assert Message.get_registered("feature") is None
    assert parsed.command == "feature"
    assert parsed.raw_payload == b"future payload"
