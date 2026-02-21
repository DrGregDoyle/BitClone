"""
The Blockchain class
"""
import json
import time
from pathlib import Path

from src.block.block import Block
from src.blockchain.genesis_block import genesis_block
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
    # TODO: Add special add_genesis function which will add the known genesis block. To be called when Blockchain is
    # first created
    TWO_WEEK_SECONDS = 20160
    MAX_WEIGHT = 4_000_000  # 4 million wu max

    def __init__(self, db_path: Path = DB_PATH):
        # --- Main db
        self.db = BitCloneDatabase(db_path)

        # --- State tracking
        self._height: int = self.db.get_chain_height()
        self._tip: Block | None = self.db.get_latest_block()
        self._difficulty: int = 0

        # --- Add genesis block
        if self.height == -1:
            self.add_block(genesis_block)

    def wipe_chain(self):
        """
        Wipes db and resets height and tip
        Returns:
        """
        self.db.wipe_db()
        self._height: int = -1
        self._tip: Block | None = None
        self.add_block(genesis_block)

    @property
    def block_subsidy(self):

        halvings = max(0, self.height // 210_000)

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
        try:
            # --- Validate before doing anything
            if not self._validate_block(block):
                logger.error(f"Block failed validation: {block.block_id.hex()}")
                return False

            # Determine block height
            new_height = self.height + 1

            # Add block to storage (dat files and db)
            self.db.add_block(block, new_height)

            # Update UTXO set
            self._update_utxo_set(block, new_height)

            # Update instance variables
            self._height = new_height
            self._tip = block

            # Adjust difficulty every 2016 blocks
            self._adjust_target()

            return True

        except Exception as e:
            logger.error(f"Error adding block: {e}")
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

        # --- Genesis block: only check PoW and coinbase
        if self.tip is None:
            block_target = bits_to_target(block.bits)
            # print(f"BITS: {block.bits.hex()}")
            # print(f"INT TARGET: {0x00000000ffff0000000000000000000000000000000000000000000000000000}")
            # print(f"BLOCK TARGET: {int.from_bytes(block_target, 'big')}")
            # print(f"BLOCK ID: {int.from_bytes(block.block_id, 'little')}")
            # print(
            #     f"TARGET MINUS BLOCK_ID: {int.from_bytes(block_target, 'big') - int.from_bytes(block.block_id, 'little')}")

            if int.from_bytes(block.block_id, 'little') >= int.from_bytes(block_target, 'big'):
                logger.error("Genesis block fails proof of work")
                return False
            # Fall through to coinbase validation below
        else:
            # --- Prev block check only applies to non-genesis
            if self.tip.block_id != block.prev_block:
                logger.error(f"Previous block_id in chain {self.tip.block_id.hex()} doesn't match "
                             f"prev_block in block: {block.prev_block.hex()}")
                return False
        # --- Timestamp check: block must not be more than 2 hours in the future
        current_time = int(time.time())
        if block.timestamp > current_time + 7200:
            logger.error(f"Block timestamp {block.timestamp} is more than 2 hours in the future")
            return False

        # --- Difficulty hash check
        block_target = bits_to_target(block.bits)
        block_hash = block.block_id
        if int.from_bytes(block_hash, 'little') >= int.from_bytes(block_target, 'big'):
            logger.error(f"Block fails proof of work validation. Current difficulty: "
                         f"{target_to_bits(block_target).hex()}")
            return False

        # === COINBASE VALIDATION === #
        if not self._validate_coinbase(block):
            logger.error("Block fails coinbase validation")
            return False

        # === NON-COINBASE TX VALIDATION === #
        # Build a temporary UTXO map for intra-block lookups
        pending_utxos: dict[bytes, UTXO] = {}

        seen_outpoints = set()
        for tx in block.txs[1:]:
            # --- Locktime check (BIP65)
            if tx.locktime > 0 and any(txin.sequence < 0xffffffff for txin in tx.inputs):
                if tx.locktime < 500_000_000:
                    # Block-height based
                    if tx.locktime >= (self.height + 1):
                        logger.error(
                            f"Tx {tx.txid.hex()} locktime {tx.locktime} not yet reached at height {self.height + 1}")
                        return False
                else:
                    # Unix timestamp based
                    if tx.locktime > int(time.time()):
                        logger.error(f"Tx {tx.txid.hex()} locktime {tx.locktime} not yet reached")
                        return False

            for txin in tx.inputs:
                # Check pending intra-block UTXOs first, then fall back to DB
                utxo = pending_utxos.get(txin.outpoint) or self.db.get_utxo(txin.outpoint)
                if utxo is None:
                    logger.error(f"Input references missing UTXO: {txin.outpoint.hex()}")
                    return False

                # --- Coinbase maturity check
                if utxo.is_coinbase:
                    if (self.height + 1) - utxo.block_height < 100:  # COINBASE_MATURITY
                        logger.error(f"Coinbase UTXO spent before maturity: {txin.outpoint.hex()}")
                        return False

                # --- Intra-block double spend
                if txin.outpoint in seen_outpoints:
                    logger.error(f"Double spend detected within block: {txin.outpoint.hex()}")
                    return False
                seen_outpoints.add(txin.outpoint)

                # --- Relative locktime per input (BIP68)
                sequence = txin.sequence
                # Bit 31 set = BIP68 disabled for this input
                if sequence & (1 << 31):
                    continue

                if sequence & (1 << 22):
                    # Time-based: lower 16 bits * 512 seconds
                    required_seconds = (sequence & 0xffff) * 512
                    utxo = self.db.get_utxo(txin.outpoint)
                    # Get the block the UTXO was confirmed in and check elapsed time
                    utxo_block = self.db.get_block_at_height(utxo.block_height)
                    elapsed = block.timestamp - utxo_block.timestamp
                    if elapsed < required_seconds:
                        logger.error(f"Relative timelock not met for input {txin.outpoint.hex()}")
                        return False
                else:
                    # Block-based: lower 16 bits = number of blocks since UTXO confirmed
                    required_blocks = sequence & 0xffff
                    utxo = self.db.get_utxo(txin.outpoint)
                    blocks_since = (self.height + 1) - utxo.block_height
                    if blocks_since < required_blocks:
                        logger.error(f"Relative block locktime not met for input {txin.outpoint.hex()}")
                        return False

            # After validating this tx, add its outputs to the pending map
            for vout, output in enumerate(tx.outputs):
                utxo = UTXO.from_txoutput(
                    txid=tx.txid,
                    vout=vout,
                    txoutput=output,
                    block_height=self.height + 1,
                    is_coinbase=False
                )
                pending_utxos[utxo.outpoint()] = utxo

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

    def _validate_coinbase(self, block: Block) -> bool:
        """
        We validate the coinbase tx in the block
        """
        coinbase_tx = block.txs[0]
        # --- Verify 1st tx in block is coinbase
        if not coinbase_tx.is_coinbase:
            logger.error(f"First tx in block not coinbase tx: {coinbase_tx.txid}")
            return False
        # --- Verify no other tx is a coinbase
        if any(tx.is_coinbase for tx in block.txs[1:]):
            logger.error("Cannot have more than one coinbase per block")
            return False
        # --- Verify coinbase output value
        coinbase_output_value = sum(txout.amount for txout in coinbase_tx.outputs)
        total_fees = sum(self._get_tx_fee(tx) for tx in block.txs[1:])  # All non-coinbase tx fees
        if coinbase_output_value > self.block_subsidy + total_fees:
            logger.error("Output value on coinbase tx exceeds block_subsidy + total fees")
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
        if input_total >= output_total:
            fee = input_total - output_total
            # --- Logging
            logger.info("--- Fee Calculation ---")
            logger.info(f"txid: {tx.txid}")
            logger.info(f"input total: {input_total}")
            logger.info(f"output total: {output_total}")
            logger.info(f"tx fee: {fee}")
            return fee
        raise TransactionError(f"Input fee: {input_total}, Output fee: {output_total}. Negative fee value: "
                               f"{output_total - input_total} for tx {tx.txid}")

    def _adjust_target(self):
        """
        After a block gets added, if the height is = 0 (mod 2016), we adjust the target based on the previous average mining gap in the previous 2016 blocks.

         Uses Bitcoin's retargeting algorithm:
            new_target = old_target * actual_timespan / TWO_WEEK_SECONDS
        Clamped to a max adjustment of 4x in either direction.
        """
        # Only retarget every 2016 blocks, and never on genesis
        if self._height == 0 or self._height % 2016 != 0:
            return

    def to_dict(self) -> dict:
        """
        Return current stats of the blockchain
        """
        return {
            "height": self._height,
            "difficulty": self._difficulty,
            "last_block": self.tip.to_dict() if self.tip else None
        }

    def to_json(self):
        return json.dumps(self.to_dict())


# --- TESTING --- #
if __name__ == "__main__":
    sep = "=" * 128
    test_blockchain = Blockchain()
    test_blockchain.wipe_chain()
    print(f"TEST BLOCKCHAIN: {test_blockchain.to_json()}")
