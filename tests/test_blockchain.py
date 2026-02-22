"""
Tests for the Blockchain and related classes
"""
from pathlib import Path

from src.blockchain.blockchain import Blockchain
from src.blockchain.genesis_block import genesis_block
from tests.conftest import make_outpoint

TEST_DB_PATH = Path(__file__).parent / "db_files" / "test_blockchain.db"


def test_genesis_block():
    """
    We verify that a new Blockchain object is created with the official genesis block as block at index 0
    """
    # --- Delete db file
    TEST_DB_PATH.unlink(missing_ok=True)

    # --- Create new blockchain
    test_blockchain = Blockchain(db_path=TEST_DB_PATH)

    # --- All new blockchains should have genesis_block as tip
    assert test_blockchain.tip == genesis_block, "New blockchain does not have genesis block as first block."

    # --- Wipe chain. Should still have genesis block as tip
    test_blockchain.wipe_chain()
    assert test_blockchain.tip == genesis_block, ("New blockchain after wiping does not have genesis block as first "
                                                  "block.")

    # --- Check UTXO set
    genesis_coinbase = genesis_block.txs[0]
    # outpoint = genesis_coinbase.txid + (0).to_bytes(4, "little")  # txid + vout index
    outpoint = make_outpoint(genesis_coinbase.txid, 0)
    utxo = test_blockchain.get_utxo(outpoint)

    assert utxo is not None, "Genesis coinbase UTXO not found in UTXO set"
    assert utxo.amount == 5_000_000_000, f"Genesis UTXO amount incorrect: {utxo.amount}"
    assert utxo.is_coinbase, "Genesis UTXO should be marked as coinbase"
    assert utxo.block_height == 0, f"Genesis UTXO block height should be 0, got {utxo.block_height}"
