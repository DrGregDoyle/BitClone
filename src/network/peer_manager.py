"""Maintain the node's target number of outbound peer connections."""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable, Iterable

from src.core import get_logger
from src.network.datatypes.network_types import PeerState
from src.network.peer import Peer
from src.network.peer_address_book import PeerAddressBook, PeerKey

__all__ = ["PeerManager"]

logger = get_logger(__name__)

ConnectPeer = Callable[[str, int], Peer]
ReadyPeers = Callable[[], Iterable[Peer]]
BootstrapPeers = Callable[[], object]


class PeerManager:
    """Fill outbound slots and defer repeatedly failing endpoints."""

    def __init__(
            self,
            address_book: PeerAddressBook,
            connect_peer: ConnectPeer,
            ready_peers: ReadyPeers,
            bootstrap_peers: BootstrapPeers | None = None,
            target_outbound: int = 8,
            base_backoff: float = 1.0,
            max_backoff: float = 300.0,
            jitter_fraction: float = 0.2,
            poll_interval: float = 1.0,
            clock: Callable[[], float] = time.monotonic,
            random_value: Callable[[], float] = random.random,
    ):
        if not isinstance(target_outbound, int) or isinstance(target_outbound, bool) or target_outbound < 0:
            raise ValueError("Outbound peer target must be a non-negative integer")
        if base_backoff <= 0 or max_backoff < base_backoff:
            raise ValueError("Backoff bounds must be positive and ordered")
        if not 0 <= jitter_fraction <= 1:
            raise ValueError("Jitter fraction must be between zero and one")
        if poll_interval <= 0:
            raise ValueError("Peer-manager poll interval must be positive")

        self.address_book = address_book
        self.target_outbound = target_outbound
        self.base_backoff = float(base_backoff)
        self.max_backoff = float(max_backoff)
        self.jitter_fraction = float(jitter_fraction)
        self.poll_interval = float(poll_interval)
        self._connect_peer = connect_peer
        self._ready_peers = ready_peers
        self._bootstrap_peers = bootstrap_peers
        self._clock = clock
        self._random_value = random_value
        self._retry_at: dict[PeerKey, float] = {}
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Start slot maintenance; repeated calls are harmless."""
        if self.is_running:
            return
        self._stop_event.clear()
        self._wake_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="bitclone-peer-manager",
            daemon=True,
        )
        self._thread.start()

    def stop(self, join_timeout: float = 5.0) -> None:
        """Request worker shutdown and wait briefly for an active attempt."""
        thread = self._thread
        if thread is None:
            return
        self._stop_event.set()
        self._wake_event.set()
        if thread is not threading.current_thread():
            thread.join(timeout=join_timeout)
        if not thread.is_alive():
            self._thread = None

    def wake(self) -> None:
        """Prompt the worker to fill a newly opened slot immediately."""
        self._wake_event.set()

    def retry_at(self, peer_key: PeerKey) -> float | None:
        """Return the monotonic retry deadline for an endpoint."""
        return self._retry_at.get(peer_key)

    def maintain(self) -> tuple[Peer, ...]:
        """Make one synchronous attempt to fill all currently open slots."""
        ready = tuple(
            peer for peer in self._ready_peers()
            if peer.state is PeerState.READY
        )
        open_slots = max(0, self.target_outbound - len(ready))
        if open_slots == 0:
            return ()

        now = self._clock()
        connected: list[Peer] = []
        ready_keys = {peer.key for peer in ready}
        for address in self.address_book.candidates(exclude=ready_keys):
            if len(connected) >= open_slots:
                break
            if self._retry_at.get(address.key, 0) > now:
                continue
            try:
                peer = self._connect_peer(str(address.host), address.port)
            except Exception as error:
                self._schedule_retry(address.key, now)
                logger.warning(
                    f"Outbound connection to {address.host}:{address.port} failed: {error}"
                )
                continue
            self._retry_at.pop(address.key, None)
            connected.append(peer)
        return tuple(connected)

    def _run(self) -> None:
        if self._bootstrap_peers is not None and len(self.address_book) == 0:
            try:
                self._bootstrap_peers()
            except Exception as error:
                logger.warning(f"Peer bootstrap failed: {error}")

        while not self._stop_event.is_set():
            try:
                self.maintain()
            except Exception as error:
                logger.exception(f"Peer maintenance iteration failed: {error}")
            self._wake_event.wait(self.poll_interval)
            self._wake_event.clear()

    def _schedule_retry(self, peer_key: PeerKey, now: float) -> None:
        entry = self.address_book.get(*peer_key)
        failures = max(1, entry.consecutive_failures if entry is not None else 1)
        exponent = min(failures - 1, 30)
        base_delay = min(self.max_backoff, self.base_backoff * (2 ** exponent))
        jitter_scale = 1 + self.jitter_fraction * ((2 * self._random_value()) - 1)
        delay = min(self.max_backoff, max(0.0, base_delay * jitter_scale))
        self._retry_at[peer_key] = now + delay
