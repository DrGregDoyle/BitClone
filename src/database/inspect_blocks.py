#!/usr/bin/env python3
"""
Inspector tool for .dat block files
Reads and decodes blocks from blkXXXXX.dat files
"""
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))
from src.chain.block import Block
from src.database import BitCloneDatabase


def inspect_block_file(file_path: Path, max_blocks: int = 10):
    """
    Read and display blocks from a .dat file

    Args:
        file_path: Path to blkXXXXX.dat file
        max_blocks: Maximum number of blocks to display
    """
    if not file_path.exists():
        print(f"Error: File {file_path} not found")
        return

    file_size = file_path.stat().st_size
    print(f"File: {file_path.name}")
    print(f"Size: {file_size:,} bytes ({file_size / 1024 / 1024:.2f} MB)")
    print("=" * 70)

    with open(file_path, 'rb') as f:
        block_count = 0
        offset = 0

        while offset < file_size and block_count < max_blocks:
            f.seek(offset)

            # Try to read a block
            try:
                # Read enough bytes for initial parsing
                chunk = f.read(80)  # Block header is 80 bytes
                if len(chunk) < 80:
                    break

                # Seek back and try to parse full block
                f.seek(offset)

                # We need to know block size - read progressively
                # This is tricky without knowing the exact size beforehand
                # For now, read a large chunk
                block_data = f.read(1024 * 1024)  # Read up to 1MB

                try:
                    block = Block.from_bytes(block_data)
                    block_size = block.length

                    print(f"\nBlock #{block_count} at offset {offset}")
                    print("-" * 70)

                    header = block.get_header()
                    print(f"  Hash:      {header.block_id[::-1].hex()}")
                    print(f"  Prev Hash: {block.prev_block[::-1].hex()}")
                    print(f"  Version:   {block.version}")
                    print(f"  Timestamp: {block.timestamp}")
                    print(f"  Nonce:     {block.nonce}")
                    print(f"  Txs:       {len(block.txs)}")
                    print(f"  Size:      {block_size} bytes")

                    # Show first transaction (coinbase)
                    if block.txs:
                        coinbase = block.txs[0]
                        print(f"  Coinbase:  {coinbase.txid[::-1].hex()}")

                    offset += block_size
                    block_count += 1

                except Exception as e:
                    print(f"  Error parsing block at offset {offset}: {e}")
                    break

            except Exception as e:
                print(f"Error reading at offset {offset}: {e}")
                break

        print("\n" + "=" * 70)
        print(f"Total blocks found: {block_count}")


def inspect_from_database(db_path: Path, block_identifier):
    """
    Inspect a block using the database index

    Args:
        db_path: Path to database
        block_identifier: Either block height (int) or block hash (hex string)
    """
    db = BitCloneDatabase(db_path)

    # Determine if identifier is height or hash
    if isinstance(block_identifier, int) or block_identifier.isdigit():
        height = int(block_identifier)
        print(f"Looking up block at height {height}...")
        block = db.get_block_at_height(height)
    else:
        # Assume it's a hex hash
        block_hash = bytes.fromhex(block_identifier)[::-1]  # Reverse for internal format
        print(f"Looking up block with hash {block_identifier}...")
        block = db.get_block(block_hash)

    if block is None:
        print("Block not found!")
        return

    print("=" * 70)
    header = block.get_header()
    print(f"Block Hash:      {header.block_id[::-1].hex()}")
    print(f"Previous Hash:   {block.prev_block[::-1].hex()}")
    print(f"Merkle Root:     {header.merkle_root[::-1].hex()}")
    print(f"Version:         {block.version}")
    print(f"Timestamp:       {block.timestamp}")
    print(f"Bits:            {header.bits.hex()}")
    print(f"Nonce:           {block.nonce}")
    print(f"Transactions:    {len(block.txs)}")
    print(f"Block Size:      {block.length} bytes")
    print("=" * 70)

    # Show transactions
    print(f"\nTransactions ({len(block.txs)}):")
    for i, tx in enumerate(block.txs):
        coinbase_flag = " (COINBASE)" if tx.is_coinbase else ""
        print(f"  {i}: {tx.txid[::-1].hex()}{coinbase_flag}")
        print(f"      Inputs: {len(tx.inputs)}, Outputs: {len(tx.outputs)}")

    # Option to show full block JSON
    show_full = input("\nShow full block JSON? (y/n): ").strip().lower()
    if show_full == 'y':
        print("\n" + block.to_json())


def list_all_blocks(db_path: Path):
    """List all blocks in the database"""
    db = BitCloneDatabase(db_path)
    height = db.get_chain_height()

    if height < 0:
        print("No blocks in database")
        return

    print(f"Blockchain height: {height}")
    print("=" * 70)

    for h in range(min(height + 1, 20)):  # Show first 20 blocks
        block = db.get_block_at_height(h)
        if block:
            header = block.get_header()
            print(f"{h:6d}: {header.block_id[::-1].hex()} ({len(block.txs)} txs)")

    if height >= 20:
        print(f"... ({height - 19} more blocks)")


def main():
    if len(sys.argv) < 2:
        print("Block Inspector Tool")
        print("=" * 70)
        print("Usage:")
        print("  # Inspect a .dat file directly")
        print("  python inspect_blocks.py blocks/blk00000.dat")
        print()
        print("  # Inspect block by height using database")
        print("  python inspect_blocks.py --db database/db_files/bitclone.db --height 0")
        print()
        print("  # Inspect block by hash using database")
        print("  python inspect_blocks.py --db database/db_files/bitclone.db --hash <hex>")
        print()
        print("  # List all blocks")
        print("  python inspect_blocks.py --db database/db_files/bitclone.db --list")
        return

    if sys.argv[1] == "--db":
        if len(sys.argv) < 4:
            print("Error: Missing database path or command")
            return

        db_path = Path(sys.argv[2])
        command = sys.argv[3]

        if command == "--list":
            list_all_blocks(db_path)
        elif command == "--height" and len(sys.argv) >= 5:
            inspect_from_database(db_path, sys.argv[4])
        elif command == "--hash" and len(sys.argv) >= 5:
            inspect_from_database(db_path, sys.argv[4])
        else:
            print("Invalid command. Use --list, --height <n>, or --hash <hex>")
    else:
        # Direct file inspection
        file_path = Path(sys.argv[1])
        max_blocks = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        inspect_block_file(file_path, max_blocks)


if __name__ == "__main__":
    main()
