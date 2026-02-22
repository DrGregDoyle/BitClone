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
from src.tx import TxIn
from src.tx.tx import UTXO, Transaction

logger = get_logger(__name__)

__all__ = ["Blockchain"]

COINBASE_MATURITY = 100


class Blockchain:
    """
    Manages the blockchain: blocks, UTXO set, and blockchain state.

    Cached state (updated on add_block):
        _height         : current chain height
        _tip            : current tip Block
        _block_subsidy  : current coinbase reward in satoshis
        _target         : current difficulty target as bytes
    """

    # --- Constants
    TWO_WEEK_SECONDS = 20_160
    HALVING_INTERVAL = 210_000
    MAX_WEIGHT = 4_000_000  # 4 million WU
    INITIAL_SUBSIDY = 5_000_000_000  # 50 BTC in satoshis
    GENESIS_BLOCK_BITS = bytes.fromhex("1d00ffff")

    # --- Construction/Reset

    def __init__(self, db_path: Path = DB_PATH):
        # --- Main db
        self.db = BitCloneDatabase(db_path)
        self.utxo_stats = {}  # Dictionary for tracking status of UTXO set

        # --- State tracking
        self._height: int = self.db.get_chain_height()
        self._tip: Block | None = self.db.get_latest_block()
        self._block_subsidy: int = self.calc_subsidy(self._height)
        self._target: bytes = bits_to_target(self.GENESIS_BLOCK_BITS)

        # --- Add genesis block
        if self.height == -1:
            self.add_block(genesis_block)

    def wipe_chain(self):
        """
        Wipes db and resets height and tip
        TODO: Will have to disable this if Blockchain goes live
        """
        self.db.wipe_db()
        self._height: int = -1
        self._tip: Block | None = None
        self.add_block(genesis_block)

    # --- Blockchain calculations
    @staticmethod
    def calc_subsidy(height: int) -> int:
        """
        Calculate the block subsidy at a given height.
        Halves every HALVING_INTERVAL blocks; zero after 64 halvings.
        """
        halvings = max(0, height // Blockchain.HALVING_INTERVAL)
        return 0 if halvings >= 64 else Blockchain.INITIAL_SUBSIDY >> halvings

    def _adjust_target(self):
        """
        Adjusts _target instance variables if conditions are met.
        """
        pass

    # --- Properties

    @property
    def block_subsidy(self):
        return self._block_subsidy

    @property
    def height(self) -> int:
        return self._height

    @property
    def tip(self) -> Block | None:
        return self._tip

    @property
    def target(self) -> bytes:
        return self._target

    @property
    def bits(self) -> bytes:
        return target_to_bits(self._target)

    # --- GET methods

    def get_block(self, block_hash: bytes) -> Block | None:
        """Retrieve a block by its hash"""
        return self.db.get_block(block_hash)

    def get_block_at_height(self, height: int) -> Block | None:
        """Retrieve a block by its height"""
        return self.db.get_block_at_height(height)

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

    # --- Add block

    def add_block(self, block: Block) -> bool:
        """
        Validate and append a block to the chain, then update all state.

        Returns:
            True if the block was accepted, False otherwise.
        """
        try:
            if not self._validate_block(block):
                logger.error(f"Block failed validation: {block.block_id.hex()}")
                return False

            new_height = self._height + 1

            self.db.add_block(block, new_height)
            self._update_utxo_set(block, new_height)

            # Update cached state
            self._height = new_height
            self._tip = block
            self._block_subsidy = self.calc_subsidy(new_height)
            self._adjust_target()

            return True

        except Exception as e:
            logger.error(f"Error adding block: {e}")
            return False

    # --- UTXO management

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

    # --- Block validation

    def _validate_block(self, block: Block) -> bool:
        """
        Full block validation against current chain state.
        Returns True only if the block may be appended as the next block.
        """
        # --- Get validation elements
        block_header = block.get_header()

        # --- Genesis block: check prev_block is all 0's
        if self.tip is None:
            if block.prev_block != b'\x00' * 32:
                logger.error("Genesis block txin has incorrect value")
                return False
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

        if not self.validate_pow(block):
            logger.error("Block failed pow validation")
            return False

        # --- Weight
        if block.weight > self.MAX_WEIGHT:
            logger.error(f"Block weight {block.weight} WU exceeds max {self.MAX_WEIGHT} WU")
            return False

        # --- Merkle root
        calc_root = MerkleTree([tx.txid for tx in block.txs]).merkle_root
        if calc_root != block_header.merkle_root:
            logger.error(f"Merkle root mismatch: calculated {calc_root.hex()}")
            return False

        # --- Coinbase
        if not self._validate_coinbase(block):
            return False

        # --- Non-coinbase transactions
        if not self._validate_block_txs(block):
            return False

        return True

    @staticmethod
    def validate_pow(block: Block) -> bool:
        """
        Returns True if block_id is smaller than the target indicated by the block.bits. False otherwise.
        NB:
            bits -> target decoding yields big-endian bytes object
            block_id uses little-endian encoding
        """
        return int.from_bytes(block.block_id, "little") < int.from_bytes(bits_to_target(block.bits), "big")

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
        coinbase_out = sum(txout.amount for txout in coinbase_tx.outputs)
        total_fees = sum(self._get_tx_fee(tx) for tx in block.txs[1:])  # All non-coinbase tx fees
        if coinbase_out > self.block_subsidy + total_fees:
            logger.error(f"Coinbase output {coinbase_out} exceeds subsidy {self._block_subsidy} + fees {total_fees}")
            return False

        # --- All clear
        return True

    def _validate_block_txs(self, block: Block) -> bool:
        """
        Validate all non-coinbase transactions in a block.
        Builds a pending UTXO map to support intra-block dependencies.
        """
        pending_utxos: dict[bytes, UTXO] = {}
        seen_outpoints: set[bytes] = set()
        next_height = self._height + 1

        for tx in block.txs[1:]:
            if not self._validate_tx(tx, block, next_height, pending_utxos, seen_outpoints):
                return False

            # Commit this tx's outputs to the pending map for subsequent txs
            for vout, output in enumerate(tx.outputs):
                utxo = UTXO.from_txoutput(
                    txid=tx.txid,
                    vout=vout,
                    txoutput=output,
                    block_height=next_height,
                    is_coinbase=False,
                )
                pending_utxos[utxo.outpoint()] = utxo

        return True

    def _validate_tx(self, tx: Transaction, block: Block, next_height: int, pending_utxos: dict[bytes, UTXO],
                     seen_outpoints: set[bytes]) -> bool:
        """
        Validate a single non-coinbase transaction.

        Args:
            tx:             Transaction to validate.
            block:          Containing block (needed for timestamp checks).
            next_height:    Height the block will be added at.
            pending_utxos:  UTXOs created by earlier txs in the same block.
            seen_outpoints: Outpoints already consumed in this block (double-spend guard).

        Returns:
            True if valid, False otherwise.
        """
        # --- BIP65 absolute locktime
        if tx.locktime > 0 and any(txin.sequence < 0xffffffff for txin in tx.inputs):
            if tx.locktime < 500_000_000:
                if tx.locktime >= next_height:
                    logger.error(f"Tx {tx.txid.hex()} absolute block-height locktime not yet reached")
                    return False
            else:
                if tx.locktime > int(time.time()):
                    logger.error(f"Tx {tx.txid.hex()} absolute time-based locktime not yet reached")
                    return False

        for txin in tx.inputs:
            utxo = pending_utxos.get(txin.outpoint) or self.db.get_utxo(txin.outpoint)

            if utxo is None:
                logger.error(f"Input references missing UTXO: {txin.outpoint.hex()}")
                return False

            # --- Coinbase maturity
            if utxo.is_coinbase and (next_height - utxo.block_height) < COINBASE_MATURITY:
                logger.error(f"Coinbase UTXO spent before maturity: {txin.outpoint.hex()}")
                return False

            # --- Intra-block double spend
            if txin.outpoint in seen_outpoints:
                logger.error(f"Double spend within block: {txin.outpoint.hex()}")
                return False
            seen_outpoints.add(txin.outpoint)

            # --- BIP68 relative locktime
            if not self._check_relative_locktime(txin, utxo, block, next_height):
                logger.error(f"Relative locktime not yet supported: {txin.outpoint.hex()}")
                return False

        return True

    def _check_relative_locktime(self, txin: TxIn, utxo: UTXO, block: Block, next_height: int) -> bool:
        """
        Validate BIP68 relative locktime for a single input.
        Returns True if the locktime is satisfied or disabled.
        """
        sequence = txin.sequence

        # Bit 31 set → BIP68 disabled for this input
        if sequence & (1 << 31):
            return True

        if sequence & (1 << 22):
            # Time-based: lower 16 bits * 512 seconds
            required_seconds = (sequence & 0xFFFF) * 512
            utxo_block = self.db.get_block_at_height(utxo.block_height)
            if block.timestamp - utxo_block.timestamp < required_seconds:
                logger.error(f"Relative time-based locktime not met for input {txin.outpoint.hex()}")
                return False
        else:
            # Block-based: lower 16 bits = required confirmations
            required_blocks = sequence & 0xFFFF
            if (next_height - utxo.block_height) < required_blocks:
                logger.error(f"Relative block-based locktime not met for input {txin.outpoint.hex()}")
                return False

        return True

    # --- Fee calculation

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
            # ---

            return fee
        raise TransactionError(f"Input fee: {input_total}, Output fee: {output_total}. Negative fee value: "
                               f"{output_total - input_total} for tx {tx.txid}")

    # --- Serialization --- #
    def to_dict(self) -> dict:
        """
        Return current stats of the blockchain
        """
        return {
            "height": self.height,
            "target": self.target.hex(),
            "bits": self.bits.hex(),
            "block_subsidy (sats)": self.block_subsidy,
            "last_block": self.tip.get_header().to_dict() if self.tip else None,
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


# --- TESTING --- #
if __name__ == "__main__":
    sep = "=" * 128
    test_blockchain = Blockchain()
    test_blockchain.wipe_chain()
    print(f"TEST BLOCKCHAIN: {test_blockchain.to_json()}")

    known_blockone_bytes = bytes.fromhex(
        "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e362990101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000")
    block_one = Block.from_bytes(known_blockone_bytes)
    print(sep)
    print(f"ADDING BLOCK ONE")
    block_added = test_blockchain.add_block(block_one)
    print(sep)
    print(f"BLOCK ADDED: {block_added}")
    print(f"BLOCKCHAIN: {test_blockchain.to_json()}")
