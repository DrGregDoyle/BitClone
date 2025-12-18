"""
Block file management - handles reading/writing blocks to .dat files
"""
from pathlib import Path

# Bitcoin Core uses 128MB files
MAX_BLOCK_FILE_SIZE = 128 * 1024 * 1024  # 128 MB


class BlockFileManager:
    """Manages reading and writing blocks to blk*.dat files"""

    def __init__(self, blocks_dir: Path):
        self.blocks_dir = blocks_dir
        self.blocks_dir.mkdir(parents=True, exist_ok=True)

        # Track current file for writing
        self.current_file_number = self._get_latest_file_number()
        self.current_file_size = self._get_file_size(self.current_file_number)

    def _get_latest_file_number(self) -> int:
        """Find the highest numbered block file"""
        files = list(self.blocks_dir.glob("blk*.dat"))
        if not files:
            return 0

        numbers = []
        for f in files:
            try:
                # Extract number from "blk00123.dat"
                num = int(f.stem[3:])
                numbers.append(num)
            except ValueError:
                continue

        return max(numbers) if numbers else 0

    def _get_file_size(self, file_number: int) -> int:
        """Get current size of a block file"""
        path = self._get_file_path(file_number)
        return path.stat().st_size if path.exists() else 0

    def _get_file_path(self, file_number: int) -> Path:
        """Get path for a block file number"""
        return self.blocks_dir / f"blk{file_number:05d}.dat"

    def write_block(self, block_bytes: bytes) -> tuple[int, int, int]:
        """
        Write block to file, return (file_number, offset, size)

        Returns:
            tuple: (file_number, file_offset, block_size)
        """
        block_size = len(block_bytes)

        # Check if we need a new file
        if self.current_file_size + block_size > MAX_BLOCK_FILE_SIZE:
            self.current_file_number += 1
            self.current_file_size = 0

        file_path = self._get_file_path(self.current_file_number)
        file_offset = self.current_file_size

        # Append block to file
        with open(file_path, 'ab') as f:
            f.write(block_bytes)

        # Update tracking
        self.current_file_size += block_size

        return self.current_file_number, file_offset, block_size

    def read_block(self, file_number: int, file_offset: int, block_size: int) -> bytes:
        """
        Read block from file

        Args:
            file_number: Which blk file
            file_offset: Byte offset in file
            block_size: Number of bytes to read

        Returns:
            Raw block bytes
        """
        file_path = self._get_file_path(file_number)

        if not file_path.exists():
            raise FileNotFoundError(f"Block file {file_path} not found")

        with open(file_path, 'rb') as f:
            f.seek(file_offset)
            block_bytes = f.read(block_size)

        if len(block_bytes) != block_size:
            raise ValueError(f"Expected {block_size} bytes, got {len(block_bytes)}")

        return block_bytes
