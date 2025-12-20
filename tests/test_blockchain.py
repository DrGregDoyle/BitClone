"""
We test elements of the blockchain
"""
from pathlib import Path
from random import randint
from secrets import token_bytes

from src.chain import Block
from src.chain.blockchain import Blockchain
from src.tx.tx import Transaction, TxInput, TxOutput

TESTBD_PATH = Path(__file__).parent / "db_files" / "test_blockchain.db"


def create_coinbase_tx(block_height: int) -> Transaction:
    """Create a simple coinbase transaction"""
    coinbase_input = TxInput(
        txid=b'\x00' * 32,
        vout=0xffffffff,
        scriptsig=block_height.to_bytes(4, 'little') + token_bytes(20),
        sequence=0xffffffff
    )

    # Coinbase reward (simplified - not checking halving)
    coinbase_output = TxOutput(
        amount=5000000000,  # 50 BTC in satoshis
        scriptpubkey=token_bytes(25)
    )

    return Transaction(
        inputs=[coinbase_input],
        outputs=[coinbase_output],
        version=2,
        locktime=0
    )


def create_test_block(prev_hash: bytes, height: int) -> Block:
    """Create a test block"""
    coinbase = create_coinbase_tx(height)

    # Add a few regular transactions
    txs = [coinbase]
    for _ in range(3):
        tx = Transaction(
            inputs=[TxInput(
                txid=token_bytes(32),
                vout=randint(0, 5),
                scriptsig=token_bytes(100),
                sequence=0xfffffffe
            )],
            outputs=[
                TxOutput(amount=randint(100000, 1000000), scriptpubkey=token_bytes(25))
                for _ in range(2)
            ],
            version=2,
            locktime=0
        )
        txs.append(tx)

    return Block(
        version=2,
        prev_block=prev_hash,
        timestamp=1700000000 + height * 600,  # ~10 min blocks
        bits=b'\x1d\x00\xff\xff',
        nonce=randint(0, 2 ** 32 - 1),
        txs=txs
    )


# def test_basic_blockchain_ops():
#     """
#     We test basic functionality of the blockchain (BEFORE VALIDATION)
#     """
#     chain = Blockchain(TESTBD_PATH)
#     chain.db.wipe_db()  # Start fresh
#
#     # 1. Test adding genesis block
#     genesis = create_test_block(b'\x00' * 32, 0)
#     result = chain.add_block(genesis)
#
#     assert result is True, "Failed to add genesis block"
#     assert chain.height == 0, f"Expected height 0, got {chain.height}"
#     assert chain.tip is not None, "Chain tip should not be None after adding genesis"
#     assert chain.tip.get_header().block_id == genesis.get_header().block_id, "Chain tip doesn't match genesis"
#
#     # 2. Test adding multiple blocks
#     prev_hash = genesis.get_header().block_id
#     blocks = []
#
#     for height in range(1, 6):
#         block = create_test_block(prev_hash, height)
#         blocks.append(block)
#         result = chain.add_block(block)
#
#         assert result is True, f"Failed to add block at height {height}"
#         assert chain.height == height, f"Expected height {height}, got {chain.height}"
#
#         prev_hash = block.get_header().block_id
#
#     # Verify final chain height
#     assert chain.height == 5, f"Expected final height 5, got {chain.height}"
#
#     # 3. Test retrieving block by height
#     block_3 = chain.get_block_at_height(3)
#
#     assert block_3 is not None, "Block at height 3 should exist"
#     assert len(block_3.txs) == 4, f"Expected 4 transactions, got {len(block_3.txs)}"
#     assert block_3.get_header().block_id == blocks[2].get_header().block_id, "Block 3 hash mismatch"
#
#     # 4. Test UTXO lookup
#     genesis_coinbase = genesis.txs[0]
#     test_outpoint = genesis_coinbase.txid + (0).to_bytes(4, 'little')
#     utxo = chain.get_utxo(test_outpoint)
#
#     assert utxo is not None, "Genesis coinbase UTXO should exist"
#     assert utxo.amount == 5000000000, f"Expected 5B sats, got {utxo.amount}"
#     assert utxo.is_coinbase is True, "Genesis output should be marked as coinbase"
#     assert utxo.block_height == 0, f"Expected height 0, got {utxo.block_height}"
#     assert utxo.is_mature(chain.height) is False, "Coinbase at height 0 should not be mature at height 5"
#
#     # 5. Test UTXO count
#     # Each block (including genesis): 1 coinbase + 3 txs with 2 outputs each = 7 UTXOs per block
#     # Total blocks: 6 (genesis + 5 more)
#     # Total: 6 * 7 = 42 UTXOs
#     expected_utxos = 6 * 7  # 42
#     actual_utxos = chain.utxo_count()
#     assert actual_utxos == expected_utxos, f"Expected {expected_utxos} UTXOs, got {actual_utxos}"
#
#     # 6. Test retrieving non-existent block
#     non_existent = chain.get_block_at_height(999)
#     assert non_existent is None, "Non-existent block should return None"
#
#     # 7. Test retrieving block by hash
#     block_5_hash = blocks[4].get_header().block_id
#     block_5_retrieved = chain.get_block(block_5_hash)
#
#     assert block_5_retrieved is not None, "Block 5 should be retrievable by hash"
#     assert block_5_retrieved.get_header().block_id == block_5_hash, "Retrieved block hash mismatch"
#
#     # 8. Test coinbase maturity
#     # Add 95 more blocks to make genesis coinbase mature (needs 100 blocks)
#     for height in range(6, 101):
#         block = create_test_block(prev_hash, height)
#         chain.add_block(block)
#         prev_hash = block.get_header().block_id
#
#     # Now genesis coinbase should be mature
#     utxo_mature = chain.get_utxo(test_outpoint)
#     assert utxo_mature is not None, "Genesis coinbase UTXO should still exist"
#     assert utxo_mature.is_mature(chain.height) is True, "Genesis coinbase should be mature after 100 blocks"


def test_utxo_spending():
    """
    Test that spending UTXOs removes them from the set
    """
    chain = Blockchain(TESTBD_PATH)
    chain.db.wipe_db()

    # Create genesis with coinbase
    genesis = create_test_block(b'\x00' * 32, 0)
    chain.add_block(genesis)

    genesis_coinbase = genesis.txs[0]
    coinbase_outpoint = genesis_coinbase.txid + (0).to_bytes(4, 'little')

    # Verify coinbase UTXO exists
    utxo = chain.get_utxo(coinbase_outpoint)
    assert utxo is not None, "Coinbase UTXO should exist"

    # Create a block that spends the coinbase (in reality this would fail validation due to maturity)
    spending_tx = Transaction(
        inputs=[TxInput(
            txid=genesis_coinbase.txid,
            vout=0,
            scriptsig=token_bytes(100),
            sequence=0xfffffffe
        )],
        outputs=[
            TxOutput(amount=2500000000, scriptpubkey=token_bytes(25)),
            TxOutput(amount=2500000000, scriptpubkey=token_bytes(25))
        ],
        version=2,
        locktime=0
    )

    block_1_coinbase = create_coinbase_tx(1)
    block_1 = Block(
        version=2,
        prev_block=genesis.get_header().block_id,
        timestamp=1700000600,
        bits=b'\x1d\x00\xff\xff',
        nonce=12345,
        txs=[block_1_coinbase, spending_tx]
    )

    chain.add_block(block_1)

    # Original coinbase UTXO should be spent (removed)
    spent_utxo = chain.get_utxo(coinbase_outpoint)
    assert spent_utxo is None, "Spent UTXO should be removed from set"

    # New UTXOs should exist
    new_outpoint_0 = spending_tx.txid + (0).to_bytes(4, 'little')
    new_outpoint_1 = spending_tx.txid + (1).to_bytes(4, 'little')

    new_utxo_0 = chain.get_utxo(new_outpoint_0)
    new_utxo_1 = chain.get_utxo(new_outpoint_1)

    assert new_utxo_0 is not None, "New UTXO 0 should exist"
    assert new_utxo_1 is not None, "New UTXO 1 should exist"
    assert new_utxo_0.amount == 2500000000, "New UTXO 0 amount incorrect"
    assert new_utxo_1.amount == 2500000000, "New UTXO 1 amount incorrect"


def test_intra_block_dependencies():
    """
    Test that a transaction can spend an output created earlier in the same block
    """
    chain = Blockchain(TESTBD_PATH)
    chain.db.wipe_db()

    # Create genesis
    genesis = create_test_block(b'\x00' * 32, 0)
    chain.add_block(genesis)

    # Block 1: Create a transaction, then spend its output in the same block
    block_1_coinbase = create_coinbase_tx(1)

    # First transaction creates an output
    tx1 = Transaction(
        inputs=[TxInput(
            txid=token_bytes(32),
            vout=0,
            scriptsig=token_bytes(100),
            sequence=0xfffffffe
        )],
        outputs=[
            TxOutput(amount=1000000, scriptpubkey=token_bytes(25))
        ],
        version=2,
        locktime=0
    )

    # Second transaction spends the output from tx1
    tx2 = Transaction(
        inputs=[TxInput(
            txid=tx1.txid,
            vout=0,
            scriptsig=token_bytes(100),
            sequence=0xfffffffe
        )],
        outputs=[
            TxOutput(amount=500000, scriptpubkey=token_bytes(25)),
            TxOutput(amount=500000, scriptpubkey=token_bytes(25))
        ],
        version=2,
        locktime=0
    )

    block_1 = Block(
        version=2,
        prev_block=genesis.get_header().block_id,
        timestamp=1700000600,
        bits=b'\x1d\x00\xff\xff',
        nonce=12345,
        txs=[block_1_coinbase, tx1, tx2]
    )

    # This should succeed - tx1's output is created before tx2 tries to spend it
    result = chain.add_block(block_1)
    assert result is True, "Block with intra-block dependencies should be added"

    # tx1's output should be spent (not in UTXO set)
    tx1_outpoint = tx1.txid + (0).to_bytes(4, 'little')
    tx1_utxo = chain.get_utxo(tx1_outpoint)
    assert tx1_utxo is None, "tx1's output should be spent"

    # tx2's outputs should exist
    tx2_outpoint_0 = tx2.txid + (0).to_bytes(4, 'little')
    tx2_outpoint_1 = tx2.txid + (1).to_bytes(4, 'little')

    tx2_utxo_0 = chain.get_utxo(tx2_outpoint_0)
    tx2_utxo_1 = chain.get_utxo(tx2_outpoint_1)

    assert tx2_utxo_0 is not None, "tx2 output 0 should exist"
    assert tx2_utxo_1 is not None, "tx2 output 1 should exist"
    assert tx2_utxo_0.amount == 500000, "tx2 output 0 amount incorrect"
    assert tx2_utxo_1.amount == 500000, "tx2 output 1 amount incorrect"
