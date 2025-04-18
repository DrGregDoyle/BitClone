"""
The Blockchain class
"""
from pathlib import Path

from src.block import Block
from src.data import to_little_bytes
from src.db import BitCloneDatabase, DB_PATH


class Blockchain:

    def __init__(self, db_path: Path = DB_PATH):
        # Load DB
        self.db = BitCloneDatabase(db_path)

        # Get block reward
        self.block_reward = 0

    def add_block(self, new_block: Block):
        # Add UTXOS, Txs and Block to DB
        for tx in new_block.txs:
            temp_utxo_list = tx.get_utxos()
            for utxo in temp_utxo_list:
                self.db.add_utxo(utxo)
            self.db.add_transaction(tx.txid(), new_block.id, new_block.timestamp)
        self.db.add_block(
            height=self.height,
            block_hash=new_block.id,
            prev_hash=new_block.prev_block,
            timestamp=new_block.timestamp,
            merkle_root=new_block.merkle_tree.merkle_root,
            nonce=new_block.nonce
        )
        self.height += 1

    def validate_block(self, block: Block) -> bool:
        """
        Must satisfy the following conditions:
            -All transactions pass validation
            
        """
        return True

    def create_coinbase_tx(self, outputs: [list], script_sig: bytes = b''):
        coinbase_txid = b'\x00' * 32  # txid = all zeros
        cointbase_vout = 0xffffffff  # vout = max value
        script_sig = to_little_bytes(self.height) + script_sig  # BIP 34 | Current height at start of script_sig

    @property
    def last_block(self):
        return self.db.get_latest_block()

    @property
    def height(self):
        return self.db.get_block_height()


# --- TESTING
from tests.randbtc_generators import get_random_block

if __name__ == "__main__":
    test_db = Path(__file__).parent / "bitclone_db" / "test.db"
    test_chain = Blockchain(test_db)
    # test_chain.db._clear_db()
    random_block = get_random_block()
    test_chain.add_block(random_block)
    print(f"TEST CHAIN HEIGHT: {test_chain.height}")
