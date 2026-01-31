import json

import pytest

from src.core import MAGICBYTES, NetworkError
from src.cryptography import hash256
from src.network.ctrl_msg import VerAck
from src.network.header import Header
from src.network.message import Message


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
    cmd_field = raw[4:16]

    assert len(cmd_field) == 12
    assert cmd_field.startswith(b"ping")
    assert cmd_field[4:] == b"\x00" * 8

    parsed = Header.from_bytes(raw)
    assert parsed.command == "ping"


def test_header_rejects_unknown_magic_bytes():
    payload = b"abc"
    checksum = hash256(payload)[:4]
    bad_magic = b"\x01\x02\x03\x04"

    with pytest.raises(NetworkError):
        Header(command="version", size=len(payload), checksum=checksum, magic_bytes=bad_magic)


def test_header_rejects_unknown_command():
    payload = b"abc"
    checksum = hash256(payload)[:4]

    with pytest.raises(NetworkError):
        Header(command="not_a_real_command", size=len(payload), checksum=checksum, magic_bytes=MAGICBYTES.MAINNET)


def test_header_rejects_bad_checksum_length():
    with pytest.raises(NetworkError):
        Header(command="version", size=0, checksum=b"\x00\x01\x02", magic_bytes=MAGICBYTES.MAINNET)


@pytest.mark.xfail(reason="Header._validate_size currently caps at 0xffff; should allow up to 0xffffffff.")
def test_header_allows_payloads_over_64kb():
    # Bitcoin message payload size field is 4 bytes (uint32). This should be allowed.
    Header(command="version", size=0x10000, checksum=b"\x00" * 4, magic_bytes=MAGICBYTES.MAINNET)


def test_verack_serializes_to_24_byte_header_only():
    msg = VerAck()
    raw = msg.to_bytes()
    assert len(raw) == 24

    parsed = VerAck.from_bytes(raw)
    assert isinstance(parsed, VerAck)


def test_message_registry_contains_verack():
    assert Message.get_registered("verack") is VerAck


def test_to_dict_formatted_is_json_safe():
    msg = VerAck()
    json.dumps(msg.to_dict(formatted=True), indent=2)  # should not raise


def test_from_bytes_does_not_require_eof():
    msg = VerAck()
    raw = msg.to_bytes() + b"EXTRA_BYTES"
    parsed = VerAck.from_bytes(raw)
    assert isinstance(parsed, VerAck)


@pytest.mark.xfail(reason="Message.from_bytes currently does not validate checksum against payload.")
def test_checksum_mismatch_raises():
    msg = VerAck()
    raw = bytearray(msg.to_bytes())
    raw[20] ^= 0x01  # flip one bit in checksum field (bytes 20-23 of header)
    with pytest.raises(Exception):
        VerAck.from_bytes(bytes(raw))


@pytest.mark.xfail(reason="No dispatcher yet: header.command is ignored; parsing always uses the provided cls.")
def test_dispatch_by_header_command():
    msg = VerAck()
    raw = msg.to_bytes()

    # Expected future behavior:
    # - read Header
    # - look up Message.get_registered(header.command)
    # - parse with that class
    stream_header = Header.from_bytes(raw[:24])
    msg_cls = Message.get_registered(stream_header.command)
    assert msg_cls is VerAck
    parsed = msg_cls.from_bytes(raw)
    assert isinstance(parsed, VerAck)
