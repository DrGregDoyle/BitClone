import json

import pytest

from src.core import MAGICBYTES, NETWORK, NetworkError
from src.cryptography import hash256
from src.network.messages.ctrl_msg import VerAck
from src.network.messages.header import Header
from src.network.messages.message import Message, UnknownMessage

UNSUPPORTED_NAMECOIN_MAGIC = b"\xf9\xbe\xb4\xfe"


class CountingMessage(Message):
    def __init__(self, payload=b"payload"):
        super().__init__()
        self.raw_payload = payload
        self.encode_count = 0

    def _get_header(self, payload):
        return Header.from_payload(payload, "counting", self.magic_bytes)

    @classmethod
    def from_payload(cls, byte_stream):
        return cls(byte_stream)

    def to_payload(self):
        self.encode_count += 1
        return self.raw_payload

    def payload_dict(self):
        return {"payload": self.raw_payload.hex()}

    def payload_data(self):
        return {"payload": self.raw_payload.hex()}


def test_header_roundtrip_from_payload():
    payload = b"hello"
    hdr = Header.from_payload(payload, command="version", magic_bytes=MAGICBYTES.MAINNET)

    raw = hdr.to_bytes()
    parsed = Header.from_bytes(raw)

    assert parsed.magic_bytes == hdr.magic_bytes
    assert parsed.command == hdr.command
    assert parsed.size == hdr.size
    assert parsed.checksum == hdr.checksum


def test_header_command_field_is_12_bytes_padded():
    payload = b"\x00"
    hdr = Header.from_payload(payload, command="ping", magic_bytes=MAGICBYTES.MAINNET)

    raw = hdr.to_bytes()
    command_start = NETWORK.MAGIC_LENGTH
    command_end = command_start + NETWORK.COMMAND_LENGTH
    cmd_field = raw[command_start:command_end]

    assert len(cmd_field) == NETWORK.COMMAND_LENGTH
    assert cmd_field.startswith(b"ping")
    assert cmd_field[len(b"ping"):] == b"\x00" * (NETWORK.COMMAND_LENGTH - len(b"ping"))

    parsed = Header.from_bytes(raw)
    assert parsed.command == "ping"


def test_header_rejects_unknown_magic_bytes():
    payload = b"abc"
    checksum = hash256(payload)[:NETWORK.CHECKSUM_LENGTH]
    bad_magic = b"\x01\x02\x03\x04"

    with pytest.raises(NetworkError):
        Header(command="version", size=len(payload), checksum=checksum, magic_bytes=bad_magic)


def test_header_accepts_signet_magic_bytes():
    payload = b"abc"
    checksum = hash256(payload)[:NETWORK.CHECKSUM_LENGTH]

    header = Header(command="version", size=len(payload), checksum=checksum, magic_bytes=MAGICBYTES.SIGNET)

    assert header.magic_bytes == MAGICBYTES.SIGNET


def test_header_rejects_namecoin_magic_bytes():
    payload = b"abc"
    checksum = hash256(payload)[:NETWORK.CHECKSUM_LENGTH]

    with pytest.raises(NetworkError):
        Header(command="version", size=len(payload), checksum=checksum, magic_bytes=UNSUPPORTED_NAMECOIN_MAGIC)


def test_header_accepts_structurally_valid_unknown_command():
    payload = b"abc"
    checksum = hash256(payload)[:NETWORK.CHECKSUM_LENGTH]

    header = Header(
        command="futuremsg",
        size=len(payload),
        checksum=checksum,
        magic_bytes=MAGICBYTES.MAINNET,
    )

    assert Header.from_bytes(header.to_bytes()).command == "futuremsg"


def test_header_rejects_noncanonical_command_padding():
    raw_header = b"".join([
        MAGICBYTES.MAINNET,
        b"ping\x00evil".ljust(NETWORK.COMMAND_LENGTH, b"\x00"),
        (0).to_bytes(NETWORK.PAYLOAD_SIZE_LENGTH, "little"),
        hash256(b"")[:NETWORK.CHECKSUM_LENGTH],
    ])

    with pytest.raises(NetworkError, match="non-zero bytes after padding"):
        Header.from_bytes(raw_header)


def test_header_rejects_non_ascii_command():
    raw_header = b"".join([
        MAGICBYTES.MAINNET,
        b"\xff".ljust(NETWORK.COMMAND_LENGTH, b"\x00"),
        (0).to_bytes(NETWORK.PAYLOAD_SIZE_LENGTH, "little"),
        hash256(b"")[:NETWORK.CHECKSUM_LENGTH],
    ])

    with pytest.raises(NetworkError, match="not ASCII"):
        Header.from_bytes(raw_header)


def test_header_rejects_command_longer_than_field():
    with pytest.raises(NetworkError, match="Invalid command length"):
        Header(
            command="commandtoolong",
            size=0,
            checksum=hash256(b"")[:NETWORK.CHECKSUM_LENGTH],
            magic_bytes=MAGICBYTES.MAINNET,
        )


def test_header_rejects_bad_checksum_length():
    with pytest.raises(NetworkError):
        Header(command="version", size=0, checksum=b"\x00\x01\x02", magic_bytes=MAGICBYTES.MAINNET)


def test_header_allows_payloads_over_64kb():
    # Bitcoin message payload size field is 4 bytes (uint32). This should be allowed.
    Header(
        command="version",
        size=0x10000,
        checksum=b"\x00" * NETWORK.CHECKSUM_LENGTH,
        magic_bytes=MAGICBYTES.MAINNET,
    )


def test_header_accepts_maximum_protocol_payload_size():
    Header(
        command="block",
        size=NETWORK.MAX_PAYLOAD_SIZE,
        checksum=b"\x00" * NETWORK.CHECKSUM_LENGTH,
        magic_bytes=MAGICBYTES.MAINNET,
    )


def test_header_rejects_payload_over_protocol_limit():
    with pytest.raises(NetworkError, match="Invalid size value"):
        Header(
            command="block",
            size=NETWORK.MAX_PAYLOAD_SIZE + 1,
            checksum=b"\x00" * NETWORK.CHECKSUM_LENGTH,
            magic_bytes=MAGICBYTES.MAINNET,
        )


def test_verack_serializes_to_header_only():
    msg = VerAck()
    raw = msg.to_bytes()
    assert len(raw) == NETWORK.HEADER_LENGTH

    parsed = VerAck.from_bytes(raw)
    assert isinstance(parsed, VerAck)


def test_message_serialization_encodes_payload_once():
    message = CountingMessage()

    raw = message.to_bytes()

    assert raw[NETWORK.HEADER_LENGTH:] == b"payload"
    assert message.encode_count == 1


def test_message_deserialization_preserves_envelope_magic_bytes():
    message = CountingMessage()
    message.magic_bytes = MAGICBYTES.REGTEST

    parsed = CountingMessage.from_bytes(message.to_bytes())

    assert parsed.raw_payload == b"payload"
    assert parsed.magic_bytes == MAGICBYTES.REGTEST


def test_message_registry_contains_verack():
    assert Message.get_registered("verack") is VerAck


def test_unknown_message_display_preserves_command_and_payload():
    message = UnknownMessage("futuremsg", b"payload", MAGICBYTES.SIGNET)

    assert message.to_data()["header"]["command"] == "futuremsg"
    assert message.to_data()["payload"] == {
        "command": "futuremsg",
        "raw_payload": b"payload".hex(),
    }


def test_to_dict_formatted_is_json_safe():
    msg = VerAck()
    json.dumps(msg.to_dict(), indent=2)  # should not raise


def test_from_bytes_does_not_require_eof():
    msg = VerAck()
    raw = msg.to_bytes() + b"EXTRA_BYTES"
    parsed = VerAck.from_bytes(raw)
    assert isinstance(parsed, VerAck)


def test_checksum_mismatch_raises():
    msg = VerAck()
    raw = bytearray(msg.to_bytes())
    checksum_start = NETWORK.HEADER_LENGTH - NETWORK.CHECKSUM_LENGTH
    raw[checksum_start] ^= 0x01
    with pytest.raises(Exception):
        VerAck.from_bytes(bytes(raw))
#
#
# @pytest.mark.xfail(reason="No dispatcher yet: header.command is ignored; parsing always uses the provided cls.")
# def test_dispatch_by_header_command():
#     msg = VerAck()
#     raw = msg.to_bytes()
#
#     # Expected future behavior:
#     # - read Header
#     # - look up Message.get_registered(header.command)
#     # - parse with that class
#     stream_header = Header.from_bytes(raw[:24])
#     msg_cls = Message.get_registered(stream_header.command)
#     assert msg_cls is VerAck
#     parsed = msg_cls.from_bytes(raw)
#     assert isinstance(parsed, VerAck)
