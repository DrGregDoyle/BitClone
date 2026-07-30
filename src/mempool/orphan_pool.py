"""Bounded storage for transactions whose input parents are not yet known."""
from __future__ import annotations

import time
from collections import OrderedDict, defaultdict
from dataclasses import dataclass

from src.tx import Tx


@dataclass(frozen=True, slots=True)
class OrphanTx:
    """A transaction waiting for one or more parent transactions."""

    tx: Tx
    missing_parents: frozenset[bytes]
    arrival_time: int

    @property
    def vbytes(self) -> int:
        return self.tx.vbytes


class OrphanTransactionPool:
    """Size-bounded, insertion-ordered orphan transaction pool."""

    MAX_COUNT = 100
    MAX_VBYTES = 5_000_000
    MAX_TIME = 20 * 60

    def __init__(
            self,
            max_count: int = MAX_COUNT,
            max_vbytes: int = MAX_VBYTES,
            max_time: int = MAX_TIME,
    ) -> None:
        self.max_count = max_count
        self.max_vbytes = max_vbytes
        self.max_time = max_time
        self.total_vbytes = 0
        self._entries: OrderedDict[bytes, OrphanTx] = OrderedDict()
        self._by_parent: dict[bytes, set[bytes]] = defaultdict(set)

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, txid: bytes) -> bool:
        return txid in self._entries

    def add(self, tx: Tx, missing_parents: set[bytes]) -> bool:
        """Store an orphan and evict the oldest entries to remain bounded."""
        if not missing_parents or tx.txid in self._entries:
            return False
        if tx.vbytes > self.max_vbytes or self.max_count <= 0:
            return False

        entry = OrphanTx(
            tx=tx,
            missing_parents=frozenset(missing_parents),
            arrival_time=int(time.time()),
        )
        self._entries[tx.txid] = entry
        self.total_vbytes += entry.vbytes
        for parent_txid in entry.missing_parents:
            self._by_parent[parent_txid].add(tx.txid)

        while len(self) > self.max_count or self.total_vbytes > self.max_vbytes:
            oldest_txid = next(iter(self._entries))
            self.remove(oldest_txid)
        return tx.txid in self._entries

    def remove(self, txid: bytes) -> OrphanTx | None:
        """Remove and return an orphan while cleaning its parent indexes."""
        entry = self._entries.pop(txid, None)
        if entry is None:
            return None
        self.total_vbytes -= entry.vbytes
        for parent_txid in entry.missing_parents:
            dependents = self._by_parent.get(parent_txid)
            if dependents is None:
                continue
            dependents.discard(txid)
            if not dependents:
                del self._by_parent[parent_txid]
        return entry

    def pop_dependents(self, parent_txid: bytes) -> tuple[OrphanTx, ...]:
        """Remove transactions waiting on ``parent_txid`` for reconsideration."""
        txids = tuple(self._by_parent.get(parent_txid, ()))
        return tuple(
            entry
            for txid in txids
            if (entry := self.remove(txid)) is not None
        )

    def evict_expired(self, now: int | None = None) -> int:
        """Drop orphans older than the short orphan-retention window."""
        cutoff = (int(time.time()) if now is None else now) - self.max_time
        expired = [
            txid
            for txid, entry in self._entries.items()
            if entry.arrival_time < cutoff
        ]
        for txid in expired:
            self.remove(txid)
        return len(expired)
