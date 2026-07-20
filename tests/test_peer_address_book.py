from ipaddress import IPv4Address

import pytest

from src.core import NETWORK
from src.network.datatypes.network_types import PeerState, Services
from src.network.peer import Peer
from src.network.peer_address_book import PeerAddressBook, PeerSource

FIRST_PEER = "192.0.2.10"
SECOND_PEER = "198.51.100.20"


def test_peer_address_book_uses_default_port_and_deduplicates_sources():
    address_book = PeerAddressBook(default_port=NETWORK.TESTNET_PORT)

    first = address_book.add(FIRST_PEER, source=PeerSource.DNS_SEED, seen_at=10)
    duplicate = address_book.add(
        IPv4Address(FIRST_PEER),
        source=PeerSource.ADDR,
        services=Services.NODE_NETWORK,
        seen_at=20,
    )

    assert first is duplicate
    assert len(address_book) == 1
    assert duplicate.port == NETWORK.TESTNET_PORT
    assert duplicate.sources == {PeerSource.DNS_SEED, PeerSource.ADDR}
    assert duplicate.services == Services.NODE_NETWORK
    assert duplicate.first_seen == 10
    assert duplicate.last_seen == 20


def test_peer_address_book_captures_negotiated_peer_metadata():
    address_book = PeerAddressBook()
    peer = Peer(FIRST_PEER, NETWORK.MAINNET_PORT)
    peer.services = Services.NODE_NETWORK | Services.NODE_WITNESS
    peer.protocol_version = NETWORK.PROTOCOL_VERSION
    peer.user_agent = "/Satoshi:test/"
    peer.last_block = 850_000

    entry = address_book.record_success(peer, succeeded_at=30)

    assert entry.success_count == 1
    assert entry.last_success == 30
    assert entry.protocol_version == NETWORK.PROTOCOL_VERSION
    assert entry.user_agent == "/Satoshi:test/"
    assert entry.last_block == 850_000
    assert entry.services == Services.NODE_NETWORK | Services.NODE_WITNESS
    assert peer.last_success == 30


def test_peer_address_book_preserves_learned_metadata_before_reconnect():
    address_book = PeerAddressBook()
    learned_peer = Peer(FIRST_PEER, NETWORK.MAINNET_PORT)
    learned_peer.protocol_version = NETWORK.PROTOCOL_VERSION
    learned_peer.user_agent = "/Satoshi:test/"
    learned_peer.last_block = 850_000
    address_book.record_success(learned_peer, succeeded_at=30)

    address_book.add_peer(Peer(FIRST_PEER, NETWORK.MAINNET_PORT), seen_at=40)
    entry = address_book.get(FIRST_PEER)

    assert entry.protocol_version == NETWORK.PROTOCOL_VERSION
    assert entry.user_agent == "/Satoshi:test/"
    assert entry.last_block == 850_000


def test_peer_address_book_candidates_prefer_reliable_recent_peers():
    address_book = PeerAddressBook()
    failed_peer = Peer(FIRST_PEER, NETWORK.MAINNET_PORT)
    unreliable = address_book.record_failure(failed_peer, failed_at=40)
    reliable_peer = Peer(SECOND_PEER, NETWORK.MAINNET_PORT)
    reliable = address_book.record_success(reliable_peer, succeeded_at=20)

    assert address_book.candidates() == (reliable, unreliable)
    assert address_book.candidates(limit=1) == (reliable,)
    assert address_book.candidates(exclude={reliable.key}) == (unreliable,)
    assert failed_peer.state is PeerState.DISCONNECTED
    assert failed_peer.fail_count == unreliable.fail_count == 1
    assert failed_peer.last_fail == unreliable.last_failure == 40


def test_peer_address_book_display_is_structured_and_sorted():
    address_book = PeerAddressBook()
    address_book.add(SECOND_PEER, seen_at=20)
    address_book.add(FIRST_PEER, seen_at=10)

    data = address_book.to_data()

    assert data["count"] == 2
    assert [peer["host"] for peer in data["peers"]] == [FIRST_PEER, SECOND_PEER]
    assert '"default_port": 8333' in address_book.to_display()


@pytest.mark.parametrize(
    ("host", "port"),
    [
        ("not-an-ip", NETWORK.MAINNET_PORT),
        (FIRST_PEER, 0),
        (FIRST_PEER, 65_536),
        (FIRST_PEER, True),
    ],
)
def test_peer_address_book_rejects_invalid_endpoints(host, port):
    address_book = PeerAddressBook()

    with pytest.raises(ValueError):
        address_book.add(host, port)
