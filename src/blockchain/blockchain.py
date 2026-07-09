"""
The Blockchain class
"""
import json
from pathlib import Path
import time

from src.block.block import Block
from src.blockchain.genesis_block import genesis_block
from src.core import get_logger, TransactionError, TX
from src.cryptography import hash256
from src.data import bits_to_target, target_to_bits, MerkleTree
from src.database.database import BitCloneDatabase, DB_PATH
from src.tx import TxIn
from src.tx.tx import LoadedTx, UTXO, Tx
from src.tx.validation import TxValidationContext, validate_loaded_tx, validate_tx_scripts

logger = get_logger(__name__)

__all__ = ["Blockchain"]

COINBASE_MATURITY = 100
MEDIAN_TIME_SPAN = 11
MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60
MIN_COINBASE_SCRIPT_SIZE = 2
MAX_COINBASE_SCRIPT_SIZE = 100
MAX_BLOCK_SIGOP_COST = 80_000
WITNESS_SCALE_FACTOR = 4
WITNESS_RESERVED_VALUE_SIZE = 32
WITNESS_COMMITMENT_HEADER = bytes.fromhex("6a24aa21a9ed")
WITNESS_COMMITMENT_SIZE = len(WITNESS_COMMITMENT_HEADER) + 32

OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e
OP_1 = 0x51
OP_16 = 0x60
OP_CHECKSIG = 0xac
OP_CHECKSIGVERIFY = 0xad
OP_CHECKMULTISIG = 0xae
OP_CHECKMULTISIGVERIFY = 0xaf
OP_CHECKSIGADD = 0xba


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
    TWO_WEEK_SECONDS = 14 * 24 * 60 * 60
    HALVING_INTERVAL = 210_000
    MAX_WEIGHT = 4_000_000  # 4 million WU
    INITIAL_SUBSIDY = 5_000_000_000  # 50 BTC in satoshis
    GENESIS_BLOCK_BITS = bytes.fromhex("1d00ffff")

    # --- Construction/Reset

    def __init__(self, db_path: Path = DB_PATH, blocks_dir: Path | None = None):
        # --- Main db
        self.db = BitCloneDatabase(db_path, blocks_dir=blocks_dir)
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

    def close(self) -> None:
        """
        Close resources owned by the blockchain.
        """
        self.db.close()

    def shutdown(self) -> None:
        """
        Alias for close(), used by higher-level runtime coordinators.
        """
        self.close()

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
        # Only retarget every 2016 blocks
        if self._height == 0 or self._height % 2016 != 0:
            return

        # Get the block at the START of the 2016-block window
        first_block = self.get_block_at_height(self._height - 2016)
        last_block = self._tip

        # Measure how long the window actually took
        actual_time = last_block.timestamp - first_block.timestamp

        # Clamp: no more than 4x adjustment in either direction
        actual_time = max(actual_time, self.TWO_WEEK_SECONDS // 4)
        actual_time = min(actual_time, self.TWO_WEEK_SECONDS * 4)

        # Scale the target proportionally
        new_target = int.from_bytes(self._target, "big") * actual_time // self.TWO_WEEK_SECONDS

        # Clamp to genesis target as the minimum difficulty ceiling
        genesis_target = int.from_bytes(bits_to_target(self.GENESIS_BLOCK_BITS), "big")
        new_target = min(new_target, genesis_target)

        self._target = new_target.to_bytes(32, "big")

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
        """Look up a UTXO by outpoint"""
        return self.db.get_utxo(outpoint)

    def get_block_index(self, block_hash: bytes):
        """Retrieve block index metadata by block hash."""
        return self.db.get_block_index(block_hash)

    def get_best_header(self):
        """Return the indexed header with the most cumulative work."""
        return self.db.get_best_header()

    def utxo_count(self) -> int:
        """Return the total number of UTXOs in the set"""
        return self.db.count_utxos()

    def would_reorganize_to(self, block_hash: bytes) -> bool:
        """
        Return True if the indexed block has more cumulative work than the active tip.
        """
        candidate = self.db.get_block_index(block_hash)
        active_tip = self.db.get_active_tip()
        if candidate is None or active_tip is None or candidate.active:
            return False
        return candidate.chainwork > active_tip.chainwork

    def reorganize_to(self, block_hash: bytes) -> bool:
        """
        Placeholder for future active-chain reorganisation.
        """
        if not self.would_reorganize_to(block_hash):
            return False
        raise NotImplementedError("Chain reorganisation requires undo data and active-chain rewrites.")

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
            self._target = bits_to_target(block.bits)

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
                outpoint = tx.txid + vout.to_bytes(TX.VOUT, "little")
                utxo = UTXO.from_txoutput(
                    outpoint=outpoint,
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
        if not block.txs:
            logger.error("Block must contain at least one transaction")
            return False

        # --- Get validation elements
        block_header = block.get_header()
        next_height = self._height + 1

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

        if not self._validate_block_timestamp(block):
            return False

        expected_bits = self._expected_bits_for_height(next_height)
        if block.bits != expected_bits:
            logger.error(f"Block bits {block.bits.hex()} do not match expected bits {expected_bits.hex()}")
            return False

        if not self.validate_pow(block):
            logger.error("Block failed pow validation")
            return False

        # --- Weight
        if block.weight > self.MAX_WEIGHT:
            logger.error(f"Block weight {block.weight} WU exceeds max {self.MAX_WEIGHT} WU")
            return False

        # --- Sigop cost
        sigop_cost = self._block_sigop_cost(block)
        if sigop_cost > MAX_BLOCK_SIGOP_COST:
            logger.error(f"Block sigop cost {sigop_cost} exceeds max {MAX_BLOCK_SIGOP_COST}")
            return False

        # --- Duplicate txids
        txids = [tx.txid for tx in block.txs]
        if len(txids) != len(set(txids)):
            logger.error("Block contains duplicate transaction ids")
            return False

        # --- Merkle root
        calc_root = MerkleTree(txids).merkle_root
        if calc_root != block_header.merkle_root:
            logger.error(f"Merkle root mismatch: calculated {calc_root.hex()}")
            return False

        # --- Coinbase
        if not self._validate_coinbase(block, next_height):
            return False

        # --- Witness commitment
        if not self._validate_witness_commitment(block):
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

    def _validate_block_timestamp(self, block: Block, current_time: int | None = None) -> bool:
        """
        Check future-time and median-time-past rules for a candidate block.
        """
        current_time = int(time.time()) if current_time is None else current_time
        if block.timestamp > current_time + MAX_FUTURE_BLOCK_TIME:
            logger.error(f"Block timestamp {block.timestamp} is more than 2 hours in the future")
            return False

        median_time_past = self._median_time_past()
        if median_time_past is not None and block.timestamp <= median_time_past:
            logger.error(f"Block timestamp {block.timestamp} is not greater than MTP {median_time_past}")
            return False

        return True

    def _median_time_past(self) -> int | None:
        """
        Return the median timestamp of the last up-to-11 active blocks.
        """
        if self._height < 0:
            return None

        timestamps = []
        first_height = max(0, self._height - MEDIAN_TIME_SPAN + 1)
        for height in range(first_height, self._height + 1):
            block = self.get_block_at_height(height)
            if block is not None:
                timestamps.append(block.timestamp)

        if not timestamps:
            return None

        timestamps.sort()
        return timestamps[len(timestamps) // 2]

    def _expected_bits_for_height(self, height: int) -> bytes:
        """
        Return the compact target that the next block at ``height`` must use.
        """
        if height == 0:
            return self.GENESIS_BLOCK_BITS

        if height % 2016 != 0:
            return self.bits

        first_block = self.get_block_at_height(height - 2016)
        last_block = self.tip
        if first_block is None or last_block is None:
            return self.bits

        new_target = self._calculate_retarget(self._target, first_block.timestamp, last_block.timestamp)
        return target_to_bits(new_target.to_bytes(32, "big"))

    def _calculate_retarget(self, current_target: bytes, first_timestamp: int, last_timestamp: int) -> int:
        actual_time = last_timestamp - first_timestamp
        actual_time = max(actual_time, self.TWO_WEEK_SECONDS // 4)
        actual_time = min(actual_time, self.TWO_WEEK_SECONDS * 4)

        new_target = int.from_bytes(current_target, "big") * actual_time // self.TWO_WEEK_SECONDS
        genesis_target = int.from_bytes(bits_to_target(self.GENESIS_BLOCK_BITS), "big")
        return min(new_target, genesis_target)

    def _block_sigop_cost(self, block: Block) -> int:
        return sum(self._tx_sigop_cost(tx) for tx in block.txs)

    def _tx_sigop_cost(self, tx: Tx) -> int:
        sigops = 0
        for txin in tx.inputs:
            sigops += self._count_sigops(txin.scriptsig)
        for txout in tx.outputs:
            sigops += self._count_sigops(txout.scriptpubkey)
        return sigops * WITNESS_SCALE_FACTOR

    @staticmethod
    def _count_sigops(script: bytes) -> int:
        sigops = 0
        previous_opcode = None
        i = 0

        while i < len(script):
            opcode = script[i]
            i += 1

            if 1 <= opcode <= 75:
                i += opcode
                previous_opcode = opcode
                continue
            if opcode == OP_PUSHDATA1:
                if i >= len(script):
                    break
                data_len = script[i]
                i += 1 + data_len
                previous_opcode = opcode
                continue
            if opcode == OP_PUSHDATA2:
                if i + 2 > len(script):
                    break
                data_len = int.from_bytes(script[i:i + 2], "little")
                i += 2 + data_len
                previous_opcode = opcode
                continue
            if opcode == OP_PUSHDATA4:
                if i + 4 > len(script):
                    break
                data_len = int.from_bytes(script[i:i + 4], "little")
                i += 4 + data_len
                previous_opcode = opcode
                continue

            if opcode in (OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD):
                sigops += 1
            elif opcode in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
                if previous_opcode is not None and OP_1 <= previous_opcode <= OP_16:
                    sigops += previous_opcode - OP_1 + 1
                else:
                    sigops += 20

            previous_opcode = opcode

        return sigops

    def _validate_coinbase(self, block: Block, block_height: int | None = None) -> bool:
        """
        We validate the coinbase tx in the block
        """
        block_height = self._height + 1 if block_height is None else block_height
        coinbase_tx = block.txs[0]

        # --- Verify 1st tx in block is coinbase
        if not coinbase_tx.is_coinbase:
            logger.error(f"First tx in block not coinbase tx: {coinbase_tx.txid}")
            return False

        scriptsig_len = len(coinbase_tx.inputs[0].scriptsig)
        if scriptsig_len < MIN_COINBASE_SCRIPT_SIZE or scriptsig_len > MAX_COINBASE_SCRIPT_SIZE:
            logger.error(f"Coinbase script size {scriptsig_len} outside allowed range 2..100")
            return False

        if block_height > 0 and not self._validate_bip34_height(coinbase_tx.inputs[0].scriptsig, block_height):
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

    def _validate_bip34_height(self, scriptsig: bytes, block_height: int) -> bool:
        if not scriptsig:
            logger.error("Coinbase script missing BIP34 height commitment")
            return False

        push_len = scriptsig[0]
        if push_len == 0 or push_len > 5:
            logger.error(f"Coinbase BIP34 height uses invalid push length {push_len}")
            return False

        if len(scriptsig) < 1 + push_len:
            logger.error("Coinbase BIP34 height push exceeds script size")
            return False

        height_bytes = scriptsig[1:1 + push_len]
        if not self._is_minimally_encoded_script_num(height_bytes):
            logger.error("Coinbase BIP34 height is not minimally encoded")
            return False

        committed_height = self._decode_script_num(height_bytes)
        if committed_height != block_height:
            logger.error(f"Coinbase BIP34 height {committed_height} does not match block height {block_height}")
            return False

        return True

    @staticmethod
    def _decode_script_num(data: bytes) -> int:
        if not data:
            return 0

        value = int.from_bytes(data, "little")
        if data[-1] & 0x80:
            value &= ~(0x80 << (8 * (len(data) - 1)))
            return -value
        return value

    @staticmethod
    def _is_minimally_encoded_script_num(data: bytes) -> bool:
        if not data:
            return True

        if (data[-1] & 0x7f) == 0:
            if len(data) == 1 or (data[-2] & 0x80) == 0:
                return False

        return True

    def _validate_witness_commitment(self, block: Block) -> bool:
        witness_present = any(tx.is_segwit for tx in block.txs[1:])
        commitment = self._find_witness_commitment(block.txs[0])

        if not witness_present:
            return True

        if commitment is None:
            logger.error("SegWit block missing coinbase witness commitment")
            return False

        reserved_value = self._get_coinbase_witness_reserved_value(block.txs[0])
        if reserved_value is None:
            return False

        witness_root = self._witness_merkle_root(block)
        expected_commitment = hash256(witness_root + reserved_value)
        if commitment != expected_commitment:
            logger.error("Coinbase witness commitment does not match witness merkle root")
            return False

        return True

    @staticmethod
    def _find_witness_commitment(coinbase_tx: Tx) -> bytes | None:
        commitment = None
        for txout in coinbase_tx.outputs:
            script = txout.scriptpubkey
            if len(script) >= WITNESS_COMMITMENT_SIZE and script[:len(WITNESS_COMMITMENT_HEADER)] == WITNESS_COMMITMENT_HEADER:
                commitment = script[len(WITNESS_COMMITMENT_HEADER):WITNESS_COMMITMENT_SIZE]
        return commitment

    @staticmethod
    def _get_coinbase_witness_reserved_value(coinbase_tx: Tx) -> bytes | None:
        if len(coinbase_tx.witness) != 1:
            logger.error("Coinbase transaction must have exactly one witness field in a SegWit block")
            return None

        witness_items = coinbase_tx.witness[0].items
        if len(witness_items) != 1 or len(witness_items[0]) != WITNESS_RESERVED_VALUE_SIZE:
            logger.error("Coinbase witness reserved value must be exactly one 32-byte stack item")
            return None

        return witness_items[0]

    @staticmethod
    def _witness_merkle_root(block: Block) -> bytes:
        wtxids = [b"\x00" * 32]
        wtxids.extend(tx.wtxid for tx in block.txs[1:])
        return MerkleTree(wtxids).merkle_root

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
                    outpoint=tx.txid + vout.to_bytes(TX.VOUT, "little"),
                    txoutput=output,
                    block_height=next_height,
                    is_coinbase=False,
                )
                pending_utxos[utxo.outpoint] = utxo

        return True

    def _validate_tx(self, tx: Tx, block: Block, next_height: int, pending_utxos: dict[bytes, UTXO],
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
        utxos: list[UTXO] = []

        for txin in tx.inputs:
            utxo = pending_utxos.get(txin.outpoint) or self.db.get_utxo(txin.outpoint)

            if utxo is None:
                logger.error(f"Input references missing UTXO: {txin.outpoint.hex()}")
                return False

            utxos.append(utxo)

        loaded_tx = LoadedTx(tx, utxos)
        validation_ctx = TxValidationContext(
            next_height=next_height,
            block_timestamp=block.timestamp,
            seen_outpoints=seen_outpoints,
            get_block_at_height=self.db.get_block_at_height,
            coinbase_maturity=COINBASE_MATURITY,
            check_locktime=True,
            check_relative_locktime=True,
            validate_scripts=True,
            script_validator=self._validate_tx_scripts,
        )

        if not validate_loaded_tx(loaded_tx, validation_ctx):
            return False

        return True

    def _validate_tx_scripts(self, tx: Tx | LoadedTx, utxos: list[UTXO] | None = None) -> bool:
        loaded_tx = tx if isinstance(tx, LoadedTx) else LoadedTx(tx, utxos)
        return validate_tx_scripts(loaded_tx)

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

    def _get_tx_fee(self, tx: Tx) -> int:
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
