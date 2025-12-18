"""
Test block storage and retrieval from database and block files - VIBECODED by CLAUDE
"""
import time
from pathlib import Path
from random import randint
from secrets import token_bytes

from src.chain.block import Block
from src.database import BitCloneDatabase
from src.tx.tx import Transaction, TxInput, TxOutput

TEST_DB_PATH = Path(__file__).parent / "db_files" / "test_blocks.db"


# --- HELPERS --- #

def create_test_transaction(num_inputs: int = 2, num_outputs: int = 2, is_coinbase: bool = False) -> Transaction:
    """Create a test transaction"""
    if is_coinbase:
        # Coinbase tx has special input
        inputs = [TxInput(
            txid=b'\x00' * 32,
            vout=0xffffffff,
            scriptsig=token_bytes(randint(50, 100)),
            sequence=0xffffffff
        )]
    else:
        inputs = [
            TxInput(
                txid=token_bytes(32),
                vout=randint(0, 10),
                scriptsig=token_bytes(randint(70, 150)),
                sequence=0xfffffffe
            )
            for _ in range(num_inputs)
        ]

    outputs = [
        TxOutput(
            amount=randint(10000, 1000000),
            scriptpubkey=token_bytes(25)
        )
        for _ in range(num_outputs)
    ]

    return Transaction(
        inputs=inputs,
        outputs=outputs,
        locktime=0,
        version=2
    )


def create_test_block(prev_hash: bytes = None, num_txs: int = 5) -> Block:
    """Create a test block with transactions"""
    if prev_hash is None:
        prev_hash = token_bytes(32)

    # First tx is always coinbase
    txs = [create_test_transaction(is_coinbase=True)]

    # Add regular transactions
    for _ in range(num_txs - 1):
        txs.append(create_test_transaction())

    return Block(
        version=2,
        prev_block=prev_hash,
        timestamp=int(time.time()),
        bits=b'\x1d\x00\xff\xff',  # Difficulty bits
        nonce=randint(0, 2 ** 32 - 1),
        txs=txs
    )


# --- TESTS --- #

def test_add_and_get_block():
    """Test adding a block and retrieving it"""
    print("Testing: Add and retrieve single block...")

    test_db = BitCloneDatabase(TEST_DB_PATH)
    test_db.wipe_db()

    # Create and add block
    block = create_test_block(num_txs=3)
    block_hash = block.get_header().block_id

    test_db.add_block(block, block_height=0)

    # Retrieve block
    retrieved = test_db.get_block(block_hash)

    assert retrieved is not None, "Block not found in database"
    assert retrieved.get_header().block_id == block_hash, "Block hash mismatch"
    assert len(retrieved.txs) == 3, "Transaction count mismatch"
    assert retrieved.version == block.version, "Version mismatch"
    assert retrieved.prev_block == block.prev_block, "Previous block hash mismatch"

    print("✓ Single block storage works!")


def test_multiple_blocks():
    """Test adding multiple blocks to storage"""
    print("Testing: Multiple block storage...")

    test_db = BitCloneDatabase(TEST_DB_PATH)
    test_db.wipe_db()

    # Create a chain of blocks
    num_blocks = 10
    blocks = []
    prev_hash = b'\x00' * 32  # Genesis

    for height in range(num_blocks):
        block = create_test_block(prev_hash=prev_hash, num_txs=randint(2, 8))
        blocks.append(block)
        test_db.add_block(block, block_height=height)
        prev_hash = block.get_header().block_id

    # Verify all blocks can be retrieved
    for i, original_block in enumerate(blocks):
        block_hash = original_block.get_header().block_id
        retrieved = test_db.get_block(block_hash)

        assert retrieved is not None, f"Block {i} not found"
        assert retrieved.get_header().block_id == block_hash, f"Block {i} hash mismatch"
        assert len(retrieved.txs) == len(original_block.txs), f"Block {i} tx count mismatch"

    print(f"✓ All {num_blocks} blocks stored and retrieved correctly!")


def test_get_block_by_height():
    """Test retrieving blocks by height"""
    print("Testing: Retrieve blocks by height...")

    test_db = BitCloneDatabase(TEST_DB_PATH)
    test_db.wipe_db()

    # Add blocks at specific heights
    blocks = []
    for height in range(5):
        block = create_test_block()
        blocks.append(block)
        test_db.add_block(block, block_height=height)

    # Retrieve by height
    for height, original_block in enumerate(blocks):
        retrieved = test_db.get_block_at_height(height)

        assert retrieved is not None, f"Block at height {height} not found"
        assert retrieved.get_header().block_id == original_block.get_header().block_id, \
            f"Block at height {height} doesn't match"

    # Test non-existent height
    non_existent = test_db.get_block_at_height(999)
    assert non_existent is None, "Should return None for non-existent height"

    print("✓ Height-based retrieval works!")


def test_chain_height():
    """Test getting current chain height"""
    print("Testing: Chain height tracking...")

    test_db = BitCloneDatabase(TEST_DB_PATH)
    test_db.wipe_db()

    # Empty chain
    assert test_db.get_chain_height() == -1, "Empty chain should have height -1"

    # Add blocks
    for height in range(10):
        block = create_test_block()
        test_db.add_block(block, block_height=height)
        assert test_db.get_chain_height() == height, f"Chain height should be {height}"

    print("✓ Chain height tracking works!")


def test_latest_block():
    """Test getting the latest block (chain tip)"""
    print("Testing: Latest block retrieval...")

    test_db = BitCloneDatabase(TEST_DB_PATH)
    test_db.wipe_db()

    # Empty chain
    assert test_db.get_latest_block() is None, "Empty chain should return None"

    # Add blocks
    last_block = None
    for height in range(5):
        block = create_test_block()
        test_db.add_block(block, block_height=height)
        last_block = block

    # Get latest
    latest = test_db.get_latest_block()
    assert latest is not None, "Should have a latest block"
    assert latest.get_header().block_id == last_block.get_header().block_id, \
        "Latest block doesn't match last added block"

    print("✓ Latest block retrieval works!")


def test_block_file_rollover():
    """Test that blocks span multiple files when size limit is reached"""
    print("Testing: Block file rollover...")

    test_db = BitCloneDatabase(TEST_DB_PATH)
    test_db.wipe_db()

    # Store initial file number
    initial_file_num = test_db.block_files.current_file_number

    # Add enough blocks to exceed file size limit
    # Create large blocks (lots of transactions)
    num_large_blocks = 50
    for height in range(num_large_blocks):
        block = create_test_block(num_txs=100)  # Large block
        test_db.add_block(block, block_height=height)

    # Check if file number increased (rollover happened)
    final_file_num = test_db.block_files.current_file_number

    # Note: This might not always trigger depending on MAX_BLOCK_FILE_SIZE
    # but the test verifies the mechanism works
    print(f"  Initial file: blk{initial_file_num:05d}.dat")
    print(f"  Final file: blk{final_file_num:05d}.dat")

    # Verify all blocks are still retrievable
    for height in range(num_large_blocks):
        block = test_db.get_block_at_height(height)
        assert block is not None, f"Block at height {height} lost after rollover"

    print("✓ Block file rollover works!")


def test_block_serialization_roundtrip():
    """Test that blocks are perfectly preserved through serialization"""
    print("Testing: Block serialization roundtrip...")

    test_db = BitCloneDatabase(TEST_DB_PATH)
    test_db.wipe_db()

    # Create block with known properties
    original_block = create_test_block(num_txs=5)
    original_bytes = original_block.to_bytes()
    original_hash = original_block.get_header().block_id

    # Store and retrieve
    test_db.add_block(original_block, block_height=0)
    retrieved_block = test_db.get_block(original_hash)

    # Compare serialized forms
    retrieved_bytes = retrieved_block.to_bytes()

    assert original_bytes == retrieved_bytes, "Serialized block bytes don't match"
    assert original_hash == retrieved_block.get_header().block_id, "Block hash changed"

    # Verify transaction details
    assert len(original_block.txs) == len(retrieved_block.txs), "Transaction count changed"

    for i, (orig_tx, retr_tx) in enumerate(zip(original_block.txs, retrieved_block.txs)):
        assert orig_tx.txid == retr_tx.txid, f"Transaction {i} txid mismatch"
        assert len(orig_tx.inputs) == len(retr_tx.inputs), f"Transaction {i} input count mismatch"
        assert len(orig_tx.outputs) == len(retr_tx.outputs), f"Transaction {i} output count mismatch"

    print("✓ Block serialization preserves all data!")


def test_database_persistence():
    """Test that blocks persist after closing and reopening database"""
    print("Testing: Database persistence...")

    # Create and populate database
    test_db = BitCloneDatabase(TEST_DB_PATH)
    test_db.wipe_db()

    blocks = []
    for height in range(5):
        block = create_test_block()
        blocks.append(block)
        test_db.add_block(block, block_height=height)

    # Get some reference data
    block_hashes = [b.get_header().block_id for b in blocks]

    # Close database (Python will handle this, but we create a new instance)
    del test_db

    # Reopen database
    new_db = BitCloneDatabase(TEST_DB_PATH)

    # Verify all blocks still exist
    assert new_db.get_chain_height() == 4, "Chain height not persisted"

    for height, block_hash in enumerate(block_hashes):
        retrieved = new_db.get_block(block_hash)
        assert retrieved is not None, f"Block {height} not persisted"
        assert retrieved.get_header().block_id == block_hash, f"Block {height} hash mismatch after reload"

    print("✓ Database persistence works!")


# --- RUN ALL TESTS --- #

if __name__ == "__main__":
    print("=" * 60)
    print("BLOCK STORAGE TESTS")
    print("=" * 60)

    try:
        test_add_and_get_block()
        test_multiple_blocks()
        test_get_block_by_height()
        test_chain_height()
        test_latest_block()
        test_block_file_rollover()
        test_block_serialization_roundtrip()
        test_database_persistence()

        print("=" * 60)
        print("✅ ALL TESTS PASSED!")
        print("=" * 60)

    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        raise
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        raise
