"""
The Blockchain class
"""
from src.block import Block
from src.db import BitCloneDatabase


class Blockchain:

    def __init__(self):
        self.db = BitCloneDatabase()
        self.height = self.db.get_block_height()

    def add_block(self, new_block: Block):
        # Add Transactions
        for tx in new_block.txs:
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

    @property
    def last_block(self):
        return self.db.get_latest_block()


# --- TESTING
from tests.randbtc_generators import get_random_block

if __name__ == "__main__":
    test_chain = Blockchain()
    # test_chain.db._clear_db()
    random_block = get_random_block()
    test_chain.add_block(random_block)
    print(f"TEST CHAIN HEIGHT: {test_chain.height}")
