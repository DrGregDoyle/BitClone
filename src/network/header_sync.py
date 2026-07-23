"""Header-first synchronization state for Bitcoin P2P peers."""
from __future__ import annotations

from enum import Enum
from typing import Callable

from src.block.block import BlockHeader
from src.blockchain.blockchain import Blockchain
from src.core import NETWORK, NetworkError
from src.network.messages.data_msg import GetHeaders, Headers
from src.network.peer import Peer

__all__ = ["HeaderSync", "HeaderSyncState"]


class HeaderSyncState(str, Enum):
    IDLE = "idle"
    SYNCING = "syncing"
    COMPLETE = "complete"
    FAILED = "failed"


class HeaderSync:
    """Request, validate, and persist consecutive batches of block headers."""

    def __init__(
            self,
            blockchain: Blockchain,
            send_message: Callable[[Peer, GetHeaders], None],
    ) -> None:
        self.blockchain = blockchain
        self._send_message = send_message
        self.state = HeaderSyncState.IDLE
        self.peer_key = None
        self.awaiting_headers = False
        self.batches_received = 0
        self.headers_received = 0

    def start(self, peer: Peer) -> GetHeaders:
        """Start or resume synchronization from the best persisted header."""
        self.peer_key = peer.key
        self.state = HeaderSyncState.SYNCING
        self.batches_received = 0
        self.headers_received = 0
        return self._request_next(peer)

    def handle_headers(self, peer: Peer, message: Headers) -> tuple[BlockHeader, ...]:
        """Process one response and request another maximum-sized batch."""
        if self.state is not HeaderSyncState.SYNCING or peer.key != self.peer_key:
            raise NetworkError(f"Unexpected headers message from {peer.host}:{peer.port}")
        if not self.awaiting_headers:
            raise NetworkError("Received headers without an outstanding getheaders request")

        self.awaiting_headers = False
        try:
            accepted = self.blockchain.add_headers(message.headers)
        except Exception:
            self.state = HeaderSyncState.FAILED
            raise

        self.batches_received += 1
        self.headers_received += len(accepted)
        if len(message.headers) == NETWORK.MAX_HEADERS_RESULTS:
            self._request_next(peer)
        else:
            self.state = HeaderSyncState.COMPLETE
        return accepted

    def peer_disconnected(self, peer: Peer) -> None:
        """Make an interrupted sync resumable from another peer."""
        if peer.key == self.peer_key and self.state is HeaderSyncState.SYNCING:
            self.state = HeaderSyncState.IDLE
            self.awaiting_headers = False
            self.peer_key = None

    def _request_next(self, peer: Peer) -> GetHeaders:
        locator = self.blockchain.get_block_locator()
        if not locator:
            raise NetworkError("Cannot synchronize headers without a known genesis header")
        request = GetHeaders(
            version=NETWORK.PROTOCOL_VERSION,
            locator_hashes=locator,
        )
        self._send_message(peer, request)
        self.awaiting_headers = True
        return request
