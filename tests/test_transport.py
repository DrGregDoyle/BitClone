import socket
from unittest.mock import MagicMock

import pytest

from src.core import MAGICBYTES, NETWORK, NetworkError
from src.network.messages.ctrl_msg import Ping
from src.network.peer import Peer
from src.network.transport import Connection, Transport


def _connected_transport_pair(magic_bytes: bytes = MAGICBYTES.MAINNET):
    left_sock, right_sock = socket.socketpair()
    peer = Peer("127.0.0.1", NETWORK.MAINNET_PORT)
    transport = Transport(magic_bytes=magic_bytes)
    transport._conns[peer.key] = Connection(left_sock, peer.key)
    return transport, peer, left_sock, right_sock


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


def test_transport_get_local_address_returns_connected_socket_endpoint():
    peer = Peer("127.0.0.1", NETWORK.MAINNET_PORT)
    fake_socket = MagicMock()
    fake_socket.getsockname.return_value = ("127.0.0.1", 49152)
    transport = Transport()
    transport._conns[peer.key] = Connection(fake_socket, peer.key)

    assert transport.get_local_address(peer) == ("127.0.0.1", 49152)
