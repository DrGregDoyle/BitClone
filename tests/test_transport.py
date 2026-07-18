import socket
from unittest.mock import MagicMock

import pytest

from src.core import MAGICBYTES, NETWORK, NetworkError
from src.network.datatypes.network_types import PeerState
from src.network.messages.ctrl_msg import Ping, Version
from src.network.messages.message import UnknownMessage
from src.network.peer import Peer
from src.network.transport import Connection, Transport

OVERSIZED_PAYLOAD_SIZE = NETWORK.MAX_PAYLOAD_SIZE + 1
IPV4_ENDPOINT = "192.0.2.10"
IPV6_ENDPOINT = "2001:db8::10"


class _ConnectSocket:
    def __init__(self, connect_error=None):
        self.connect_error = connect_error
        self.timeout = None
        self.connected_to = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, endpoint):
        if self.connect_error is not None:
            raise self.connect_error
        self.connected_to = endpoint

    def close(self):
        self.closed = True


def _address_info(family, host, port):
    if family == socket.AF_INET6:
        endpoint = (host, port, 0, 0)
    else:
        endpoint = (host, port)
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", endpoint


def _raw_header(command: str, payload_size: int, magic_bytes: bytes = MAGICBYTES.MAINNET) -> bytes:
    return b"".join([
        magic_bytes,
        command.encode("ascii").ljust(NETWORK.COMMAND_LENGTH, b"\x00"),
        payload_size.to_bytes(NETWORK.PAYLOAD_SIZE_LENGTH, "little"),
        b"\x00" * NETWORK.CHECKSUM_LENGTH,
    ])


def _connected_transport_pair(magic_bytes: bytes = MAGICBYTES.MAINNET):
    left_sock, right_sock = socket.socketpair()
    peer = Peer("127.0.0.1", NETWORK.MAINNET_PORT)
    transport = Transport(magic_bytes=magic_bytes)
    transport._conns[peer.key] = Connection(left_sock, peer.key)
    return transport, peer, left_sock, right_sock


@pytest.mark.parametrize(
    ("family", "host"),
    [(socket.AF_INET, IPV4_ENDPOINT), (socket.AF_INET6, IPV6_ENDPOINT)],
)
def test_transport_connect_uses_resolved_address_family(family, host):
    created_with = []
    fake_socket = _ConnectSocket()

    def socket_factory(*socket_options):
        created_with.append(socket_options)
        return fake_socket

    peer = Peer(host, NETWORK.MAINNET_PORT)
    endpoint = _address_info(family, host, peer.port)
    transport = Transport(
        timeout=30,
        resolver=lambda _host, _port: [endpoint],
        socket_factory=socket_factory,
    )

    transport.connect(peer)

    assert created_with == [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)]
    assert fake_socket.connected_to == endpoint[4]
    assert fake_socket.timeout == 30
    assert peer.state is PeerState.CONNECTED
    assert peer.fail_count == 0


def test_transport_connect_falls_back_to_the_next_resolved_address():
    failed_socket = _ConnectSocket(OSError("IPv6 unavailable"))
    connected_socket = _ConnectSocket()
    sockets = iter([failed_socket, connected_socket])
    addresses = [
        _address_info(socket.AF_INET6, IPV6_ENDPOINT, NETWORK.MAINNET_PORT),
        _address_info(socket.AF_INET, IPV4_ENDPOINT, NETWORK.MAINNET_PORT),
    ]
    peer = Peer("seed.example", NETWORK.MAINNET_PORT)
    transport = Transport(
        resolver=lambda _host, _port: addresses,
        socket_factory=lambda *_options: next(sockets),
    )

    transport.connect(peer)

    assert failed_socket.closed
    assert connected_socket.connected_to == (IPV4_ENDPOINT, NETWORK.MAINNET_PORT)
    assert peer.state is PeerState.CONNECTED
    assert peer.fail_count == 0


def test_transport_records_one_failure_after_all_resolved_addresses_fail():
    sockets = [_ConnectSocket(OSError("first failed")), _ConnectSocket(OSError("second failed"))]
    socket_iter = iter(sockets)
    addresses = [
        _address_info(socket.AF_INET6, IPV6_ENDPOINT, NETWORK.MAINNET_PORT),
        _address_info(socket.AF_INET, IPV4_ENDPOINT, NETWORK.MAINNET_PORT),
    ]
    peer = Peer("seed.example", NETWORK.MAINNET_PORT)
    transport = Transport(
        resolver=lambda _host, _port: addresses,
        socket_factory=lambda *_options: next(socket_iter),
    )

    with pytest.raises(ConnectionError, match="second failed"):
        transport.connect(peer)

    assert all(sock.closed for sock in sockets)
    assert peer.state is PeerState.DISCONNECTED
    assert peer.fail_count == 1
    assert peer.last_fail is not None


def test_transport_send_stamps_configured_magic_bytes():
    transport, peer, left_sock, right_sock = _connected_transport_pair(MAGICBYTES.REGTEST)
    try:
        msg = Ping(1)
        transport.send(peer, msg)

        raw = right_sock.recv(1024)
        assert raw[:4] == MAGICBYTES.REGTEST
        assert msg.magic_bytes == MAGICBYTES.REGTEST
    finally:
        left_sock.close()
        right_sock.close()


def test_transport_recv_accepts_configured_magic_bytes():
    transport, peer, left_sock, right_sock = _connected_transport_pair(MAGICBYTES.TESTNET)
    try:
        msg = Ping(123)
        msg.magic_bytes = MAGICBYTES.TESTNET
        right_sock.sendall(msg.to_bytes())

        parsed = transport.recv_one(peer)

        assert isinstance(parsed, Ping)
        assert parsed.nonce == 123
    finally:
        left_sock.close()
        right_sock.close()


def test_transport_returns_unknown_message_for_ready_peer():
    transport, peer, left_sock, right_sock = _connected_transport_pair(MAGICBYTES.SIGNET)
    peer.state = PeerState.READY
    try:
        message = UnknownMessage("futuremsg", b"payload", MAGICBYTES.SIGNET)
        right_sock.sendall(message.to_bytes())

        parsed = transport.recv_one(peer)

        assert isinstance(parsed, UnknownMessage)
        assert parsed.command == "futuremsg"
        assert parsed.raw_payload == b"payload"
        assert parsed.magic_bytes == MAGICBYTES.SIGNET
        assert peer.state is PeerState.READY
    finally:
        left_sock.close()
        right_sock.close()


def test_transport_rejects_unknown_message_with_corrupt_checksum():
    transport, peer, left_sock, right_sock = _connected_transport_pair()
    try:
        raw = bytearray(UnknownMessage("futuremsg", b"payload", MAGICBYTES.MAINNET).to_bytes())
        checksum_start = NETWORK.HEADER_LENGTH - NETWORK.CHECKSUM_LENGTH
        raw[checksum_start] ^= 0x01
        right_sock.sendall(raw)

        with pytest.raises(NetworkError, match="Failed to validate"):
            transport.recv_one(peer)
    finally:
        left_sock.close()
        right_sock.close()


def test_transport_recv_rejects_wrong_network_magic_bytes():
    transport, peer, left_sock, right_sock = _connected_transport_pair(MAGICBYTES.MAINNET)
    try:
        msg = Ping(123)
        msg.magic_bytes = MAGICBYTES.TESTNET
        right_sock.sendall(msg.to_bytes())

        with pytest.raises(NetworkError, match="Unexpected network magic bytes"):
            transport.recv_one(peer)
    finally:
        left_sock.close()
        right_sock.close()


def test_transport_recv_rejects_unexpected_command():
    transport, peer, left_sock, right_sock = _connected_transport_pair()
    try:
        msg = Ping(123)
        right_sock.sendall(msg.to_bytes())

        with pytest.raises(NetworkError, match="Unexpected command"):
            transport.recv_one(peer, expected_command=Version.COMMAND)
    finally:
        left_sock.close()
        right_sock.close()


def test_transport_get_local_address_returns_connected_socket_endpoint():
    peer = Peer("127.0.0.1", NETWORK.MAINNET_PORT)
    fake_socket = MagicMock()
    fake_socket.getsockname.return_value = ("127.0.0.1", 49152)
    transport = Transport()
    transport._conns[peer.key] = Connection(fake_socket, peer.key)

    assert transport.get_local_address(peer) == ("127.0.0.1", 49152)


def test_transport_rejects_oversized_header_without_reading_payload():
    peer = Peer("127.0.0.1", NETWORK.MAINNET_PORT)
    fake_socket = MagicMock()
    fake_socket.recv.return_value = _raw_header("futuremsg", OVERSIZED_PAYLOAD_SIZE)
    transport = Transport()
    transport._conns[peer.key] = Connection(fake_socket, peer.key)

    with pytest.raises(NetworkError, match="Invalid size value"):
        transport.recv_one(peer)

    fake_socket.recv.assert_called_once_with(NETWORK.HEADER_LENGTH)
