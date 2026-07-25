"""Periodic Bitcoin ping/pong keepalive supervision."""

from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from src.core import get_logger
from src.network.datatypes.network_types import PeerState
from src.network.messages.ctrl_msg import Ping
from src.network.peer import Peer
from src.network.peer_address_book import PeerKey

__all__ = [
    "DEFAULT_KEEPALIVE_POLL_INTERVAL",
    "DEFAULT_PING_INTERVAL",
    "DEFAULT_PONG_TIMEOUT",
    "PeerKeepalive",
]

DEFAULT_PING_INTERVAL = 120.0
DEFAULT_PONG_TIMEOUT = 20.0
DEFAULT_KEEPALIVE_POLL_INTERVAL = 1.0

logger = get_logger(__name__)

ReadyPeers = Callable[[], Iterable[Peer]]
SendPing = Callable[[Peer, Ping], None]
DisconnectPeer = Callable[[Peer], None]


@dataclass(slots=True)
class _KeepaliveState:
    peer: Peer
    next_ping_at: float
    pending_nonce: int | None = None
    ping_sent_at: float | None = None


class PeerKeepalive:
    """Send periodic pings and disconnect peers whose pong deadline expires."""

    def __init__(
            self,
            ready_peers: ReadyPeers,
            send_ping: SendPing,
            disconnect_peer: DisconnectPeer,
            ping_interval: float = DEFAULT_PING_INTERVAL,
            pong_timeout: float = DEFAULT_PONG_TIMEOUT,
            poll_interval: float = DEFAULT_KEEPALIVE_POLL_INTERVAL,
            clock: Callable[[], float] = time.monotonic,
            nonce_factory: Callable[[], int] = lambda: secrets.randbits(64),
    ):
        if ping_interval <= 0:
            raise ValueError("Ping interval must be positive")
        if pong_timeout <= 0:
            raise ValueError("Pong timeout must be positive")
        if poll_interval <= 0:
            raise ValueError("Keepalive poll interval must be positive")
        self.ping_interval = float(ping_interval)
        self.pong_timeout = float(pong_timeout)
        self.poll_interval = float(poll_interval)
        self._ready_peers = ready_peers
        self._send_ping = send_ping
        self._disconnect_peer = disconnect_peer
        self._clock = clock
        self._nonce_factory = nonce_factory
        self._states: dict[PeerKey, _KeepaliveState] = {}
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def pending_count(self) -> int:
        with self._lock:
            return sum(state.pending_nonce is not None for state in self._states.values())

    def pending_nonce(self, peer: Peer) -> int | None:
        with self._lock:
            state = self._states.get(peer.key)
            return state.pending_nonce if state is not None else None

    def start(self) -> None:
        if self.is_running:
            return
        self._stop_event.clear()
        self._wake_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="bitclone-peer-keepalive",
            daemon=True,
        )
        self._thread.start()

    def stop(self, join_timeout: float = 5.0) -> None:
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
        self._wake_event.set()

    def forget(self, peer: Peer) -> None:
        with self._lock:
            self._states.pop(peer.key, None)
        self.wake()

    def ping(self, peer: Peer) -> int:
        """Send a ping immediately and track its nonce."""
        now = self._clock()
        with self._lock:
            state = self._states.get(peer.key)
            if state is None:
                state = _KeepaliveState(peer=peer, next_ping_at=now)
                self._states[peer.key] = state
            if state.pending_nonce is not None:
                return state.pending_nonce
            nonce = self._nonce_factory()
            state.pending_nonce = nonce
            state.ping_sent_at = now
        try:
            self._send_ping(peer, Ping(nonce))
        except Exception:
            with self._lock:
                self._states.pop(peer.key, None)
            raise
        return nonce

    def handle_pong(self, peer: Peer, nonce: int) -> bool:
        """Match a pong to the peer's one outstanding ping."""
        now = self._clock()
        with self._lock:
            state = self._states.get(peer.key)
            if state is None or state.pending_nonce != nonce:
                return False
            state.pending_nonce = None
            state.ping_sent_at = None
            state.next_ping_at = now + self.ping_interval
            return True

    def maintain(self) -> tuple[Peer, ...]:
        """Run one deterministic scheduling and timeout pass."""
        now = self._clock()
        ready = {
            peer.key: peer
            for peer in self._ready_peers()
            if peer.state is PeerState.READY
        }
        with self._lock:
            for key in tuple(self._states):
                if key not in ready:
                    self._states.pop(key, None)
            for key, peer in ready.items():
                self._states.setdefault(
                    key,
                    _KeepaliveState(peer=peer, next_ping_at=now + self.ping_interval),
                )
            timed_out = tuple(
                state.peer
                for state in self._states.values()
                if (
                    state.pending_nonce is not None
                    and state.ping_sent_at is not None
                    and now - state.ping_sent_at >= self.pong_timeout
                )
            )
            for peer in timed_out:
                self._states.pop(peer.key, None)
            due = tuple(
                state.peer
                for state in self._states.values()
                if state.pending_nonce is None and now >= state.next_ping_at
            )

        for peer in timed_out:
            logger.warning(f"Peer {peer.host}:{peer.port} missed pong deadline")
            self._disconnect_peer(peer)
        sent: list[Peer] = []
        for peer in due:
            try:
                self.ping(peer)
            except Exception as error:
                logger.warning(f"Keepalive ping to {peer.host}:{peer.port} failed: {error}")
                self._disconnect_peer(peer)
                continue
            sent.append(peer)
        return tuple(sent)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.maintain()
            except Exception as error:
                logger.exception(f"Peer keepalive iteration failed: {error}")
            self._wake_event.wait(self.poll_interval)
            self._wake_event.clear()
