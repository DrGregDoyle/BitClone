"""
The Blockchain class
"""
import time
from datetime import time
from pathlib import Path

from src.block.block import Block
from src.core import get_logger, TransactionError
from src.data import bits_to_target, target_to_bits, MerkleTree
from src.database.database import BitCloneDatabase, DB_PATH
from src.tx.tx import UTXO, Transaction

logger = get_logger(__name__)

__all__ = ["Blockchain"]


class Blockchain:
    """
    Manages the blockchain: blocks, UTXO set, and blockchain state
    """
    TWO_WEEK_SECONDS = 20160
    MAX_WEIGHT = 4_000_000  # 4 million wu max

    def __init__(self, db_path: Path = DB_PATH):
        # --- Main db
        self.db = BitCloneDatabase(db_path)

        # --- State tracking
        self._height: int = self.db.get_chain_height()
        self._tip: Block | None = self.db.get_latest_block()
        self._difficulty: int = 0

    def wipe_chain(self):
        """
        Wipes db and resets height and tip
        Returns:
        """
        self.db.wipe_db()
        self._height: int = -1
        self._tip: Block | None = None

    @property
    def block_subsidy(self):

        halvings = self.height // 210_000

        # After 64 halvings, subsidy becomes zero
        if halvings >= 64:
            return 0

        # Start with 50 BTC (5,000,000,000 satoshis) and halve
        return 5_000_000_000 >> halvings

    @property
    def height(self) -> int:
        return self._height

    @property
    def tip(self) -> Block | None:
        return self._tip

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
        # --- Validate block

        try:
            # Determine block height
            new_height = self.height + 1

            # Add block to storage (dat files and db)
            self.db.add_block(block, new_height)

            # Update UTXO set
            self._update_utxo_set(block, new_height)

            # Update instance variables
            self._height = new_height
            self._tip = block

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
            block_height: Height of the block in the blockchain
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

    def _validate_block(self, block: Block) -> bool:
        """
        We validate the given block according to the blockchain state. Return True/False based on whether it's valid
        to be added as next block in the current chain
        """
        # --- Get validation elements
        block_header = block.get_header()

        if self.tip.block_id != block.prev_block:
            logger.error(f"Previous block_id in chain {self.tip.block_id.hex()} doesn't match "
                         f"prev_block in block: {block.prev_block.hex()}")
            return False
        # --- Timestamp check
        current_time = int(time.time())
        block_time = block.timestamp
        if abs(current_time - block_time) > 6400:  # Two hours in seconds
            logger.error(f"Block timestamp is outside the 2-hour period: {current_time}")
            return False

        # --- Difficulty hash check
        block_target = bits_to_target(block.bits)
        block_hash = block.block_id
        if block_hash >= block_target:
            logger.error(f"Block fails proof of work validation. Current difficulty: "
                         f"{target_to_bits(block_target).hex()}")
            return False

        # === COINBASE VALIDATION === #
        # --- Verify coinbase tx
        coinbase_tx = block.txs[0]
        if not coinbase_tx.is_coinbase:
            logger.error(f"First tx in block not coinbase tx: {coinbase_tx.txid}")
            return False
        # --- Verify no other tx is a coinbase
        if any(tx.is_coinbase for tx in block.txs[1:]):
            logger.error("Cannot have more than one coinbase per block")
            return False
        # --- Verify coinbase output value
        coinbase_output_value = sum(txout.amount for txout in coinbase_tx.outputs)

        # --- Verify weight
        if block.weight > self.MAX_WEIGHT:
            logger.error(f"Block weight ({block.weight}wu) is greater than max weight ({self.MAX_WEIGHT}wu)")
            return False

        # --- Verify MerkleRoot
        calc_merkle_root = MerkleTree([tx.txid for tx in block.txs]).merkle_root
        if calc_merkle_root != block_header.merkle_root:
            logger.error(
                f"Merkle root mismatch. Given txids don't yield attached merkle root: {calc_merkle_root.hex()}")
            return False

        # --- All clear
        return True

    def _get_input_utxos(self, tx: Transaction) -> list[UTXO]:
        """
        For a given tx we return a list of UTXOs associated with that tx
        """
        return [self.db.get_utxo(txin.outpoint) for txin in tx.inputs]

    def _get_tx_fee(self, tx: Transaction) -> int:
        """
        Given a tx, we return the sum of the ouputs minus the sum of the inputs. If this value is negative we raise
        an error.
        """
        # --- Input sums
        input_total = sum(self.db.get_utxo(txin.outpoint).amount for txin in tx.inputs)
        # --- Output sums
        output_total = sum(txout.amount for txout in tx.outputs)
        if input_total < output_total:
            fee = output_total - input_total
            # --- Logging
            logger.info("--- Fee Calculation ---")
            logger.info(f"txid: {tx.txid}")
            logger.info(f"input total: {input_total}")
            logger.info(f"output total: {output_total}")
            logger.info(f"tx fee: {fee}")
            return fee
        raise TransactionError(f"Input fee: {input_total}, Output fee: {output_total}. Negative fee value: "
                               f"{output_total - input_total} for tx {tx.txid}")


# --- TESTING --- #
if __name__ == "__main__":
    sep = "=" * 128
