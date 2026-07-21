import threading

import pytest

from src.core import NETWORK
from src.network.datatypes.network_types import PeerState
from src.network.peer import Peer
from src.network.peer_address_book import PeerAddressBook, PeerSource
from src.network.peer_manager import PeerManager


def _ready_peer(host: str, port: int = NETWORK.MAINNET_PORT) -> Peer:
    return Peer(host, port, state=PeerState.READY)


def test_peer_manager_defaults_to_eight_outbound_slots():
    manager = PeerManager(PeerAddressBook(), lambda _host, _port: None, lambda: ())

    assert manager.target_outbound == 8


def test_peer_manager_fills_target_outbound_slots():
    address_book = PeerAddressBook()
    ready = []
    attempted = []
    for suffix in range(1, 6):
        address_book.add(f"192.0.2.{suffix}", source=PeerSource.DNS_SEED, seen_at=suffix)

    def connect(host, port):
        attempted.append((host, port))
        peer = _ready_peer(host, port)
        address_book.record_success(peer, source=PeerSource.DNS_SEED)
        ready.append(peer)
        return peer

    manager = PeerManager(
        address_book,
        connect,
        lambda: tuple(ready),
        target_outbound=3,
    )

    connected = manager.maintain()

    assert len(connected) == 3
    assert len(ready) == 3
    assert len(attempted) == 3
    assert manager.maintain() == ()
    assert len(attempted) == 3


def test_peer_manager_replaces_a_disconnected_peer():
    address_book = PeerAddressBook()
    first = _ready_peer("192.0.2.1")
    ready = [first]
    address_book.record_success(first)
    address_book.add("192.0.2.2", seen_at=20)

    def connect(host, port):
        peer = _ready_peer(host, port)
        address_book.record_success(peer)
        ready.append(peer)
        return peer

    manager = PeerManager(address_book, connect, lambda: tuple(ready), target_outbound=1)

    assert manager.maintain() == ()
    ready.remove(first)
    connected = manager.maintain()

    assert len(connected) == 1
    assert connected[0].state is PeerState.READY
    assert len(ready) == 1


def test_peer_manager_uses_exponential_backoff_between_failures():
    address_book = PeerAddressBook()
    entry = address_book.add("192.0.2.1", seen_at=10)
    now = [100.0]
    attempts = 0

    def connect(host, port):
        nonlocal attempts
        attempts += 1
        peer = Peer(host, port)
        address_book.record_failure(peer, failed_at=now[0])
        raise ConnectionError("unreachable")

    manager = PeerManager(
        address_book,
        connect,
        lambda: (),
        target_outbound=1,
        base_backoff=10,
        max_backoff=100,
        jitter_fraction=0,
        clock=lambda: now[0],
    )

    manager.maintain()
    assert attempts == 1
    assert manager.retry_at(entry.key) == 110

    now[0] = 109
    manager.maintain()
    assert attempts == 1

    now[0] = 110
    manager.maintain()
    assert attempts == 2
    assert manager.retry_at(entry.key) == 130
    assert entry.consecutive_failures == 2


@pytest.mark.parametrize(
    ("random_value", "expected_retry"),
    [(0.0, 108.0), (1.0, 112.0)],
    ids=["negative-jitter", "positive-jitter"],
)
def test_peer_manager_applies_bounded_jitter(random_value, expected_retry):
    address_book = PeerAddressBook()
    entry = address_book.add("192.0.2.1")

    def connect(host, port):
        address_book.record_failure(Peer(host, port), failed_at=100)
        raise ConnectionError("unreachable")

    manager = PeerManager(
        address_book,
        connect,
        lambda: (),
        target_outbound=1,
        base_backoff=10,
        max_backoff=100,
        jitter_fraction=0.2,
        clock=lambda: 100,
        random_value=lambda: random_value,
    )

    manager.maintain()

    assert manager.retry_at(entry.key) == expected_retry


def test_peer_manager_success_clears_backoff_and_consecutive_failures():
    address_book = PeerAddressBook()
    entry = address_book.add("192.0.2.1")
    now = [100.0]
    should_fail = [True]
    ready = []

    def connect(host, port):
        peer = Peer(host, port)
        if should_fail[0]:
            address_book.record_failure(peer, failed_at=now[0])
            raise ConnectionError("unreachable")
        peer.transition(PeerState.READY)
        address_book.record_success(peer, succeeded_at=now[0])
        ready.append(peer)
        return peer

    manager = PeerManager(
        address_book,
        connect,
        lambda: tuple(ready),
        target_outbound=1,
        base_backoff=10,
        jitter_fraction=0,
        clock=lambda: now[0],
    )

    manager.maintain()
    should_fail[0] = False
    now[0] = 110
    assert len(manager.maintain()) == 1

    assert manager.retry_at(entry.key) is None
    assert entry.consecutive_failures == 0


def test_peer_manager_worker_bootstraps_and_connects_until_stopped():
    address_book = PeerAddressBook()
    ready = []
    connected = threading.Event()
    bootstrap_calls = 0

    def bootstrap():
        nonlocal bootstrap_calls
        bootstrap_calls += 1
        address_book.add("192.0.2.1", source=PeerSource.DNS_SEED)

    def connect(host, port):
        peer = _ready_peer(host, port)
        address_book.record_success(peer, source=PeerSource.DNS_SEED)
        ready.append(peer)
        connected.set()
        return peer

    manager = PeerManager(
        address_book,
        connect,
        lambda: tuple(ready),
        bootstrap_peers=bootstrap,
        target_outbound=1,
        poll_interval=0.01,
    )

    manager.start()
    try:
        assert connected.wait(timeout=1)
        assert manager.is_running
        assert bootstrap_calls == 1
        manager.start()
        assert bootstrap_calls == 1
    finally:
        manager.stop()

    assert not manager.is_running


@pytest.mark.parametrize("target", [-1, True])
def test_peer_manager_rejects_invalid_outbound_target(target):
    with pytest.raises(ValueError, match="non-negative integer"):
        PeerManager(PeerAddressBook(), lambda _host, _port: None, lambda: (), target_outbound=target)
