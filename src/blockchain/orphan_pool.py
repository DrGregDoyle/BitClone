"""Bounded storage for blocks whose parents are not known yet."""
from __future__ import annotations

from collections import OrderedDict, defaultdict
from dataclasses import dataclass
import threading
import time

from src.block.block import Block

__all__ = ["OrphanBlockPool"]


@dataclass(frozen=True, slots=True)
class _OrphanEntry:
    block: Block
    size: int
    added_at: float


class OrphanBlockPool:
    """Keep a bounded, insertion-ordered set of parentless block bodies."""

    def __init__(self, max_blocks: int = 100, max_bytes: int = 100 * 1024 * 1024):
        if max_blocks < 1:
            raise ValueError("max_blocks must be positive")
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        self.max_blocks = max_blocks
        self.max_bytes = max_bytes
        self._entries: OrderedDict[bytes, _OrphanEntry] = OrderedDict()
        self._children: dict[bytes, set[bytes]] = defaultdict(set)
        self._total_bytes = 0
        self._lock = threading.RLock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def __contains__(self, block_hash: bytes) -> bool:
        with self._lock:
            return block_hash in self._entries

    @property
    def total_bytes(self) -> int:
        with self._lock:
            return self._total_bytes

    def add(self, block: Block, *, added_at: float | None = None) -> bool:
        block_bytes = block.to_bytes()
        size = len(block_bytes)
        if size > self.max_bytes:
            return False
        with self._lock:
            if block.block_id in self._entries:
                return False
            entry = _OrphanEntry(
                block=block,
                size=size,
                added_at=time.time() if added_at is None else added_at,
            )
            self._entries[block.block_id] = entry
            self._children[block.prev_block].add(block.block_id)
            self._total_bytes += size
            while len(self._entries) > self.max_blocks or self._total_bytes > self.max_bytes:
                oldest_hash = next(iter(self._entries))
                self._remove(oldest_hash)
            return block.block_id in self._entries

    def pop_children(self, parent_hash: bytes) -> tuple[Block, ...]:
        """Remove and return direct children of a newly accepted parent."""
        with self._lock:
            child_hashes = tuple(self._children.pop(parent_hash, ()))
            children = []
            for child_hash in child_hashes:
                entry = self._entries.get(child_hash)
                if entry is not None:
                    children.append(entry.block)
                    self._remove(child_hash)
            return tuple(children)

    def _remove(self, block_hash: bytes) -> _OrphanEntry | None:
        entry = self._entries.pop(block_hash, None)
        if entry is None:
            return None
        siblings = self._children.get(entry.block.prev_block)
        if siblings is not None:
            siblings.discard(block_hash)
            if not siblings:
                self._children.pop(entry.block.prev_block, None)
        self._total_bytes -= entry.size
        return entry
