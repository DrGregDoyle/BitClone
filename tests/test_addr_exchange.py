from unittest.mock import MagicMock, call

import pytest

from src.core import NETWORK
from src.network.datatypes.network_data import NetAddr
from src.network.datatypes.network_types import PeerState, Services
from src.network.messages.ctrl_msg import Addr, Ping
from src.network.peer import Peer
from src.network.peer_address_book import PeerSource
from src.node.node import Node

SOURCE_HOST = "192.0.2.10"
LEARNED_HOST = "198.51.100.20"
SECOND_LEARNED_HOST = "2001:db8::20"


def _ready_peer(host: str, port: int) -> Peer:
    return Peer(host, port, state=PeerState.READY)


def test_receive_addr_merges_addresses_and_relays_to_two_other_ready_peers(
        monkeypatch,
        tmp_path,
):
    node = Node(db_path=tmp_path / "node.db")
    source = _ready_peer(SOURCE_HOST, NETWORK.MAINNET_PORT)
    recipients = [
        _ready_peer(f"192.0.2.{suffix}", NETWORK.MAINNET_PORT)
        for suffix in (11, 12, 13)
    ]
    message = Addr([
        NetAddr(LEARNED_HOST, NETWORK.MAINNET_PORT, Services.NODE_NETWORK, timestamp=10),
        NetAddr(SECOND_LEARNED_HOST, NETWORK.MAINNET_PORT, Services.NODE_WITNESS, timestamp=20),
    ])
    node._ready_peers = {peer.key: peer for peer in (source, *recipients)}
    node.transport.recv_one = MagicMock(return_value=message)
    node.transport.send = MagicMock()
    monkeypatch.setattr(
        "src.node.node.random.sample",
        lambda candidates, count: candidates[:count],
    )

    try:
        received = node.receive_peer_message(source)

        assert received is message
        assert node.address_book.get(LEARNED_HOST).sources == {PeerSource.ADDR}
        assert node.address_book.get(SECOND_LEARNED_HOST).services == Services.NODE_WITNESS
        assert node.transport.send.call_args_list == [
            call(recipients[0], message),
            call(recipients[1], message),
        ]
    finally:
        node.close()


def test_addr_relay_excludes_source_and_disconnected_peers(monkeypatch, tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    source = _ready_peer(SOURCE_HOST, NETWORK.MAINNET_PORT)
    ready = _ready_peer("192.0.2.11", NETWORK.MAINNET_PORT)
    disconnected = Peer("192.0.2.12", NETWORK.MAINNET_PORT)
    node._ready_peers = {peer.key: peer for peer in (source, ready, disconnected)}
    node.transport.send = MagicMock()
    monkeypatch.setattr(
        "src.node.node.random.sample",
        lambda candidates, count: candidates[:count],
    )

    try:
        node.handle_peer_message(source, Addr([]))

        node.transport.send.assert_called_once()
        assert node.transport.send.call_args.args[0] is ready
    finally:
        node.close()


def test_non_addr_message_is_ignored_by_addr_handler(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    peer = _ready_peer(SOURCE_HOST, NETWORK.MAINNET_PORT)
    node._ready_peers[peer.key] = peer
    node.transport.send = MagicMock()

    try:
        assert node.handle_peer_message(peer, Ping(1)) == ()
        node.transport.send.assert_not_called()
    finally:
        node.close()


def test_receive_peer_message_rejects_unready_peer(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    peer = Peer(SOURCE_HOST, NETWORK.MAINNET_PORT)

    try:
        with pytest.raises(ConnectionError, match="not ready"):
            node.receive_peer_message(peer)
    finally:
        node.close()
