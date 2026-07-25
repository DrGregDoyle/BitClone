import socket
from unittest.mock import MagicMock

import pytest

from src.core import MAGICBYTES, NETWORK, NetworkDataError, NetworkError
from src.network.datatypes.network_types import PeerState
from src.network.messages.ctrl_msg import Ping
from src.network.peer import Peer
from src.network.peer_address_book import PeerAddressBook
from src.network.peer_discipline import (
    DEFAULT_BAN_DURATION,
    DEFAULT_BAN_THRESHOLD,
    PeerDiscipline,
    PeerMisbehaviour,
)
from src.network.peer_manager import PeerManager
from src.node.node import Node


def test_misbehaviour_scores_reach_threshold_and_ban_host_across_ports():
    discipline = PeerDiscipline()

    for expected_score in (20, 40, 60, 80, 100):
        assert discipline.record("192.0.2.50", PeerMisbehaviour.MALFORMED_MESSAGE) == expected_score

    assert PeerMisbehaviour.MALFORMED_MESSAGE.score == 20
    assert discipline.score("192.0.2.50") == DEFAULT_BAN_THRESHOLD
    assert discipline.is_banned("192.0.2.50")
    assert discipline.is_banned("192.0.2.50")
    assert discipline.ban("192.0.2.50").reason == "malformed-message"


def test_invalid_network_data_uses_stronger_score():
    assert PeerMisbehaviour.INVALID_DATA.score == 50
    assert (
        Node._classify_peer_error(NetworkDataError("invalid header"))
        is PeerMisbehaviour.INVALID_DATA
    )


def test_ban_expires_and_clears_accumulated_score():
    now = [1_000.0]
    discipline = PeerDiscipline(clock=lambda: now[0])
    for _ in range(5):
        discipline.record("192.0.2.51", PeerMisbehaviour.PROTOCOL_VIOLATION)

    ban = discipline.ban("192.0.2.51")
    assert ban.banned_until == now[0] + DEFAULT_BAN_DURATION
    assert len(discipline.active_bans()) == 1

    now[0] += DEFAULT_BAN_DURATION

    assert not discipline.is_banned("192.0.2.51")
    assert discipline.score("192.0.2.51") == 0
    assert discipline.active_bans() == ()


def test_peer_manager_skips_banned_outbound_candidates():
    address_book = PeerAddressBook()
    address_book.add("192.0.2.52")
    address_book.add("192.0.2.53")
    discipline = PeerDiscipline()
    for _ in range(5):
        discipline.record("192.0.2.52", PeerMisbehaviour.MALFORMED_MESSAGE)
    attempted = []

    def connect(host, port):
        attempted.append((host, port))
        return Peer(host, port, state=PeerState.READY)

    manager = PeerManager(
        address_book=address_book,
        connect_peer=connect,
        ready_peers=lambda: (),
        target_outbound=1,
        is_banned=discipline.is_banned,
    )

    connected = manager.maintain()

    assert [peer.host for peer in connected] == ["192.0.2.53"]
    assert attempted == [("192.0.2.53", NETWORK.MAINNET_PORT)]


def test_malformed_messages_disconnect_and_accumulate_toward_ban(tmp_path):
    discipline = PeerDiscipline()
    node = Node(db_path=tmp_path / "node.db", peer_discipline=discipline)
    node.transport.recv_one = MagicMock(
        side_effect=[NetworkError("Failed to validate header and payload")] * 5
    )
    node.transport.disconnect = MagicMock(
        side_effect=lambda candidate: candidate.transition(PeerState.DISCONNECTED)
    )

    try:
        for attempt in range(5):
            peer = Peer(
                "192.0.2.54",
                NETWORK.MAINNET_PORT + attempt,
                state=PeerState.READY,
            )
            node.address_book.add_peer(peer)
            node._ready_peers[peer.key] = peer
            sibling = None
            if attempt == 4:
                sibling = Peer(
                    "192.0.2.54",
                    NETWORK.MAINNET_PORT + 100,
                    state=PeerState.READY,
                )
                node.address_book.add_peer(sibling)
                node._ready_peers[sibling.key] = sibling

            with pytest.raises(NetworkError, match="Failed to validate"):
                node.receive_peer_message(peer)

            assert peer.state is PeerState.DISCONNECTED
            assert peer not in node.ready_peers
            if sibling is not None:
                assert sibling.state is PeerState.DISCONNECTED
                assert sibling not in node.ready_peers

        assert discipline.is_banned("192.0.2.54")
        with pytest.raises(ConnectionError, match="temporarily banned"):
            node.connect_peer("192.0.2.54", NETWORK.MAINNET_PORT)
    finally:
        node.close()


def test_corrupt_checksum_is_scored_from_real_transport_frame(tmp_path):
    discipline = PeerDiscipline()
    node = Node(db_path=tmp_path / "node.db", peer_discipline=discipline)
    node_sock, remote_sock = socket.socketpair()
    peer = Peer("127.0.0.1", NETWORK.MAINNET_PORT)
    node.transport.adopt_socket(peer, node_sock)
    peer.transition(PeerState.READY)
    node.address_book.add_peer(peer)
    node._ready_peers[peer.key] = peer
    raw = bytearray(Ping(123).to_bytes())
    raw[:4] = MAGICBYTES.MAINNET
    checksum_start = NETWORK.HEADER_LENGTH - NETWORK.CHECKSUM_LENGTH
    raw[checksum_start] ^= 0x01

    try:
        remote_sock.sendall(raw)

        with pytest.raises(NetworkError, match="Failed to validate"):
            node.receive_peer_message(peer)

        assert discipline.score("127.0.0.1") == PeerMisbehaviour.MALFORMED_MESSAGE.score
        assert peer.state is PeerState.DISCONNECTED
    finally:
        remote_sock.close()
        node.close()


def test_connection_failures_disconnect_without_misbehaviour_score(tmp_path):
    discipline = PeerDiscipline()
    node = Node(db_path=tmp_path / "node.db", peer_discipline=discipline)
    peer = Peer("192.0.2.55", NETWORK.MAINNET_PORT, state=PeerState.READY)
    node.address_book.add_peer(peer)
    node._ready_peers[peer.key] = peer
    node.transport.recv_one = MagicMock(side_effect=ConnectionError("peer closed"))
    node.transport.disconnect = MagicMock(
        side_effect=lambda candidate: candidate.transition(PeerState.DISCONNECTED)
    )

    try:
        with pytest.raises(ConnectionError, match="peer closed"):
            node.receive_peer_message(peer)

        assert discipline.score("192.0.2.55") == 0
        assert not discipline.is_banned("192.0.2.55")
    finally:
        node.close()


def test_banned_inbound_peer_is_rejected_before_socket_adoption(tmp_path):
    discipline = PeerDiscipline()
    for _ in range(5):
        discipline.record("192.0.2.56", PeerMisbehaviour.MALFORMED_MESSAGE)
    node = Node(db_path=tmp_path / "node.db", peer_discipline=discipline)
    sock = MagicMock()
    sock.getpeername.return_value = ("192.0.2.56", 49152)

    try:
        with pytest.raises(ConnectionError, match="temporarily banned"):
            node.accept_peer(sock)

        sock.close.assert_called_once_with()
        assert node.ready_peers == ()
    finally:
        node.close()
