"""
Tests for the Blockchain and related classes
"""
from pathlib import Path

from src.blockchain.blockchain import Blockchain
from src.blockchain.genesis_block import genesis_block as GB

TEST_DB_PATH = Path(__file__).parent / "db_files" / "test_blockchain.db"


def test_genesis_block():
    """
    We verify that a new Blockchain object is created with the official genesis block as block at index 0
    """
    test_blockchain = Blockchain(db_path=TEST_DB_PATH)
    test_blockchain.wipe_chain()
    
    # --- All new blockchains should have genesis_block as tip
    assert test_blockchain.tip == GB, "New blockchain does not have genesis block as first block."
