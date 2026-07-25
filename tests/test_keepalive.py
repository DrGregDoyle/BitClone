from unittest.mock import MagicMock

import pytest

from src.core import NETWORK, NetworkError
from src.network.datatypes.network_types import PeerState
from src.network.keepalive import PeerKeepalive
from src.network.messages.ctrl_msg import Ping, Pong
from src.network.peer import Peer
from src.node.node import Node


def _ready_peer() -> Peer:
    return Peer("192.0.2.70", NETWORK.MAINNET_PORT, state=PeerState.READY)


def test_keepalive_schedules_periodic_ping_for_ready_peer():
    now = [100.0]
    peer = _ready_peer()
    sent = []
    keepalive = PeerKeepalive(
        ready_peers=lambda: (peer,),
        send_ping=lambda candidate, message: sent.append((candidate, message)),
        disconnect_peer=lambda _peer: None,
        ping_interval=10,
        pong_timeout=3,
        clock=lambda: now[0],
        nonce_factory=lambda: 123,
    )

    assert keepalive.maintain() == ()
    now[0] = 109.9
    assert keepalive.maintain() == ()
    now[0] = 110

    assert keepalive.maintain() == (peer,)
    assert sent[0][0] is peer
    assert isinstance(sent[0][1], Ping)
    assert sent[0][1].nonce == 123
    assert keepalive.pending_nonce(peer) == 123


def test_keepalive_matches_only_outstanding_pong_nonce_and_reschedules():
    now = [200.0]
    peer = _ready_peer()
    sent = []
    keepalive = PeerKeepalive(
        ready_peers=lambda: (peer,),
        send_ping=lambda candidate, message: sent.append((candidate, message)),
        disconnect_peer=lambda _peer: None,
        ping_interval=10,
        pong_timeout=3,
        clock=lambda: now[0],
        nonce_factory=lambda: 456,
    )

    assert keepalive.ping(peer) == 456
    assert not keepalive.handle_pong(peer, 999)
    assert keepalive.pending_nonce(peer) == 456
    assert keepalive.handle_pong(peer, 456)
    assert keepalive.pending_nonce(peer) is None

    now[0] = 209.9
    assert keepalive.maintain() == ()
    now[0] = 210
    assert keepalive.maintain() == (peer,)


def test_keepalive_disconnects_peer_after_pong_timeout():
    now = [300.0]
    peer = _ready_peer()
    disconnected = []
    keepalive = PeerKeepalive(
        ready_peers=lambda: (peer,),
        send_ping=lambda _peer, _message: None,
        disconnect_peer=lambda candidate: disconnected.append(candidate),
        ping_interval=10,
        pong_timeout=3,
        clock=lambda: now[0],
        nonce_factory=lambda: 789,
    )
    keepalive.ping(peer)

    now[0] = 302.9
    keepalive.maintain()
    assert disconnected == []
    now[0] = 303
    keepalive.maintain()

    assert disconnected == [peer]
    assert keepalive.pending_nonce(peer) is None


def test_node_replies_to_ping_with_matching_pong(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    peer = _ready_peer()
    node._ready_peers[peer.key] = peer
    node.transport.send = MagicMock()

    try:
        ping = Ping(321)
        assert node.handle_peer_message(peer, ping) == ()

        node.transport.send.assert_called_once()
        assert node.transport.send.call_args.args[0] is peer
        pong = node.transport.send.call_args.args[1]
        assert isinstance(pong, Pong)
        assert pong.nonce == 321
    finally:
        node.close()


def test_unexpected_pong_disconnects_and_scores_peer(tmp_path):
    node = Node(db_path=tmp_path / "node.db")
    peer = _ready_peer()
    node.address_book.add_peer(peer)
    node._ready_peers[peer.key] = peer
    node.transport.send = MagicMock()
    nonce = node.keepalive.ping(peer)
    node.transport.recv_one = MagicMock(return_value=Pong(nonce ^ 1))

    try:
        with pytest.raises(NetworkError, match="Unexpected pong nonce"):
            node.receive_peer_message(peer)

        assert peer.state is PeerState.DISCONNECTED
        assert node.peer_discipline.score(str(peer.host)) == 20
    finally:
        node.close()
