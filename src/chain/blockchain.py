"""
The Blockchain class
"""
from pathlib import Path

from src.chain.block import Block
from src.database.database import BitCloneDatabase, DB_PATH
from src.tx.tx import UTXO

__all__ = ["Blockchain"]


class Blockchain:
    """
    Manages the blockchain: blocks, UTXO set, and chain state
    """

    def __init__(self, db_path: Path = DB_PATH):
        self.db = BitCloneDatabase(db_path)

    @property
    def height(self) -> int:
        """Current blockchain height"""
        return self.db.get_chain_height()

    @property
    def tip(self) -> Block | None:
        """Get the latest block (chain tip)"""
        return self.db.get_latest_block()

    def get_block(self, block_hash: bytes) -> Block | None:
        """Retrieve a block by its hash"""
        return self.db.get_block(block_hash)

    def get_block_at_height(self, height: int) -> Block | None:
        """Retrieve a block by its height"""
        return self.db.get_block_at_height(height)

    def add_block(self, block: Block) -> bool:
        """
        Add a block to the blockchain and update UTXO set

        Args:
            block: Block to add

        Returns:
            True if successful, False otherwise
        """
        try:
            # Determine block height
            new_height = self.height + 1

            # Add block to storage
            self.db.add_block(block, new_height)

            # Update UTXO set
            self._update_utxo_set(block, new_height)

            return True

        except Exception as e:
            print(f"Error adding block: {e}")
            return False

    def _update_utxo_set(self, block: Block, block_height: int):
        """
        Update UTXO set for a block
        Process transactions in order to handle intra-block dependencies

        Args:
            block: Block whose transactions to process
            block_height: Height of the block in the chain
        """
        for tx in block.txs:
            # Step 1: Remove spent UTXOs (skip for coinbase)
            if not tx.is_coinbase:
                for inp in tx.inputs:
                    self.db.remove_utxo(inp.outpoint)

            # Step 2: Add new UTXOs from this transaction
            for vout, output in enumerate(tx.outputs):
                utxo = UTXO.from_txoutput(
                    txid=tx.txid,
                    vout=vout,
                    txoutput=output,
                    block_height=block_height,
                    is_coinbase=tx.is_coinbase
                )
                self.db.add_utxo(utxo)

    def get_utxo(self, outpoint: bytes) -> UTXO | None:
        """
        Look up a UTXO by outpoint

        Args:
            outpoint: 36-byte outpoint (txid + vout)

        Returns:
            UTXO if found, None otherwise
        """
        return self.db.get_utxo(outpoint)

    def utxo_count(self) -> int:
        """Return the total number of UTXOs in the set"""
        return self.db.count_utxos()


# --- TESTING --- #
if __name__ == "__main__":
    sep = "=" * 128
