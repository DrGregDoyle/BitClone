"""Track inventory objects requested from peers but not yet delivered."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from src.network.datatypes.network_data import InvVector
from src.network.datatypes.network_types import InvType
from src.network.peer_address_book import PeerKey

__all__ = ["InflightInventory", "InventoryKey", "InventoryRequest", "inventory_key"]

InventoryKey = tuple[str, bytes]

TX_INVENTORY_TYPES = frozenset({InvType.MSG_TX, InvType.MSG_WITNESS_TX})
BLOCK_INVENTORY_TYPES = frozenset({
    InvType.MSG_BLOCK,
    InvType.MSG_FILTERED_BLOCK,
    InvType.MSG_CMPCT_BLOCK,
    InvType.MSG_WITNESS_BLOCK,
    InvType.MSG_FILTERED_WITNESS_BLOCK,
})


def inventory_key(vector: InvVector) -> InventoryKey | None:
    """Map wire inventory variants to their underlying object identity."""
    if vector.inv_type in TX_INVENTORY_TYPES:
        return "tx", vector.obj_hash
    if vector.inv_type in BLOCK_INVENTORY_TYPES:
        return "block", vector.obj_hash
    return None


@dataclass(frozen=True, slots=True)
class InventoryRequest:
    vector: InvVector
    peer_key: PeerKey
    requested_at: float


class InflightInventory:
    """Deduplicate inventory requests across peers until delivery or timeout."""

    def __init__(
            self,
            timeout: float = 60.0,
            clock: Callable[[], float] = time.monotonic,
    ):
        if timeout <= 0:
            raise ValueError("Inventory request timeout must be positive")
        self.timeout = float(timeout)
        self._clock = clock
        self._requests: dict[InventoryKey, InventoryRequest] = {}
        self._lock = threading.RLock()

    def __len__(self) -> int:
        with self._lock:
            self._expire_locked(self._clock())
            return len(self._requests)

    def claim(self, vector: InvVector, peer_key: PeerKey) -> bool:
        """Claim an object for one peer, returning false if already in flight."""
        key = inventory_key(vector)
        if key is None:
            return False
        now = self._clock()
        with self._lock:
            self._expire_locked(now)
            if key in self._requests:
                return False
            self._requests[key] = InventoryRequest(vector, peer_key, now)
            return True

    def contains(self, vector: InvVector) -> bool:
        key = inventory_key(vector)
        if key is None:
            return False
        with self._lock:
            self._expire_locked(self._clock())
            return key in self._requests

    def release(self, vector: InvVector) -> bool:
        key = inventory_key(vector)
        if key is None:
            return False
        return self.release_key(key)

    def release_key(self, key: InventoryKey) -> bool:
        with self._lock:
            return self._requests.pop(key, None) is not None

    def release_peer(self, peer_key: PeerKey) -> int:
        """Release every request assigned to a disconnected peer."""
        with self._lock:
            keys = [key for key, request in self._requests.items() if request.peer_key == peer_key]
            for key in keys:
                del self._requests[key]
            return len(keys)

    def expire(self) -> int:
        with self._lock:
            return self._expire_locked(self._clock())

    def _expire_locked(self, now: float) -> int:
        expired = [
            key for key, request in self._requests.items()
            if now - request.requested_at >= self.timeout
        ]
        for key in expired:
            del self._requests[key]
        return len(expired)
