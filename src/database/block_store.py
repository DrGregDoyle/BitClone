"""Pluggable block-body storage for archival and pruned nodes."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from src.database.block_files import BlockFileManager

__all__ = [
    "ArchivalBlockStore",
    "BlockLocation",
    "BlockStore",
    "PrunedBlockStore",
]


@dataclass(frozen=True, slots=True)
class BlockLocation:
    file_number: int
    file_offset: int
    block_size: int


class BlockStore(ABC):
    """Storage boundary used by the block index database."""

    def __init__(self, blocks_dir: Path) -> None:
        self.blocks_dir = Path(blocks_dir)
        self.blocks_dir.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def write_block(self, block_bytes: bytes) -> BlockLocation:
        raise NotImplementedError

    @abstractmethod
    def read_block(self, location: BlockLocation) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def delete_block(self, location: BlockLocation) -> bool:
        raise NotImplementedError

    @abstractmethod
    def clear(self) -> int:
        raise NotImplementedError


class ArchivalBlockStore(BlockStore):
    """Append block bodies to packed 128 MB files and retain them indefinitely."""

    def __init__(self, blocks_dir: Path) -> None:
        super().__init__(blocks_dir)
        self.manager = BlockFileManager(self.blocks_dir)

    def write_block(self, block_bytes: bytes) -> BlockLocation:
        return BlockLocation(*self.manager.write_block(block_bytes))

    def read_block(self, location: BlockLocation) -> bytes:
        return self.manager.read_block(
            location.file_number,
            location.file_offset,
            location.block_size,
        )

    def delete_block(self, location: BlockLocation) -> bool:
        # Packed files can contain other retained blocks and are never deleted
        # individually in archival mode.
        return False

    def clear(self) -> int:
        return self.manager.clear_block_files()


class PrunedBlockStore(BlockStore):
    """Store one block per file so bodies outside the retention window are reclaimable."""

    def __init__(self, blocks_dir: Path) -> None:
        super().__init__(blocks_dir)
        existing = self._block_files()
        self.current_file_number = max((self._file_number(path) for path in existing), default=-1)

    def write_block(self, block_bytes: bytes) -> BlockLocation:
        self.current_file_number += 1
        path = self._file_path(self.current_file_number)
        path.write_bytes(block_bytes)
        return BlockLocation(self.current_file_number, 0, len(block_bytes))

    def read_block(self, location: BlockLocation) -> bytes:
        path = self._file_path(location.file_number)
        if not path.exists():
            raise FileNotFoundError(f"Block file {path} not found")
        with path.open("rb") as stream:
            stream.seek(location.file_offset)
            block_bytes = stream.read(location.block_size)
        if len(block_bytes) != location.block_size:
            raise ValueError(f"Expected {location.block_size} bytes, got {len(block_bytes)}")
        return block_bytes

    def delete_block(self, location: BlockLocation) -> bool:
        path = self._file_path(location.file_number)
        if not path.exists():
            return False
        path.unlink()
        return True

    def clear(self) -> int:
        files = self._block_files()
        for path in files:
            path.unlink()
        self.current_file_number = -1
        return len(files)

    def _block_files(self) -> list[Path]:
        return list(self.blocks_dir.glob("blk*.dat"))

    def _file_path(self, file_number: int) -> Path:
        return self.blocks_dir / f"blk{file_number:05d}.dat"

    @staticmethod
    def _file_number(path: Path) -> int:
        try:
            return int(path.stem[3:])
        except ValueError:
            return -1
