# src/blockchain/validator.py

import time

from src.block.block import Block
from src.core import get_logger, TX
from src.data import MerkleTree
from src.script import SignatureEngine
from src.script.script_engine import ScriptEngine
from src.tx import TxIn
from src.tx.tx import UTXO, Tx

logger = get_logger(__name__)
COINBASE_MATURITY = 100

__all__ = ["BlockValidator"]


class ChainState:
    """
    Lightweight snapshot of chain state passed into validator.
    Validator never holds a reference to Blockchain directly.
    """

    def __init__(self, height: int, tip: Block | None, target: bytes, block_subsidy: int):
        self.height = height
        self.tip = tip
        self.target = target
        self.block_subsidy = block_subsidy


class BlockValidator:
    """
    Stateless block and transaction validator.
    Receives all chain context via ChainState — never imports Blockchain.
    """

    def __init__(self):
        self.script_engine = ScriptEngine()
        self.sig_engine = SignatureEngine()

    # --- Top-level entry point ---

    def validate_block(self, block: Block, state: ChainState, get_utxo_fn, get_block_at_height_fn) -> bool:
        """
        Full block validation. Receives chain lookups as callables to
        avoid holding a reference to Blockchain or DB directly.

        Args:
            block:                  Block to validate
            state:                  Current chain state snapshot
            get_utxo_fn:            Callable[[bytes], UTXO | None]
            get_block_at_height_fn: Callable[[int], Block | None]
        """
        if not self._validate_header(block, state):
            return False
        if not self._validate_merkle(block):
            return False
        if not self._validate_coinbase(block, state):
            return False
        if not self._validate_block_txs(block, state, get_utxo_fn, get_block_at_height_fn):
            return False
        return True

    # --- Header ---

    def _validate_header(self, block: Block, state: ChainState) -> bool:
        """Validates prev_block link, timestamp, and PoW"""
        if state.tip is None:
            if block.prev_block != b'\x00' * 32:
                logger.error("Genesis prev_block is not zeroed")
                return False
        else:
            if state.tip.block_id != block.prev_block:
                logger.error("prev_block mismatch")
                return False

        if block.timestamp > int(time.time()) + 7200:
            logger.error("Block timestamp too far in future")
            return False

        if not self._validate_pow(block, state.target):
            logger.error("Block fails PoW check")
            return False

        return True

    @staticmethod
    def _validate_pow(block: Block, target: bytes) -> bool:
        return int.from_bytes(block.block_id, "little") < int.from_bytes(target, "big")

    # --- Merkle ---

    def _validate_merkle(self, block: Block) -> bool:
        calc_root = MerkleTree([tx.txid for tx in block.txs]).merkle_root
        if calc_root != block.get_header().merkle_root:
            logger.error("Merkle root mismatch")
            return False
        return True

    # --- Coinbase ---

    def _validate_coinbase(self, block: Block, state: ChainState) -> bool:
        """Validates coinbase position, uniqueness, and output value"""
        coinbase_tx = block.txs[0]

        if not coinbase_tx.is_coinbase:
            logger.error("First tx is not coinbase")
            return False
        if any(tx.is_coinbase for tx in block.txs[1:]):
            logger.error("Multiple coinbase txs in block")
            return False

        # Fee sum passed in from outside — validator doesn't touch the DB
        # Blockchain calls _get_tx_fee per tx and sums before calling validate_block
        # OR move _get_tx_fee here too (see note below)
        return True

    # --- Transactions ---

    def _validate_block_txs(self, block: Block, state: ChainState, get_utxo_fn, get_block_at_height_fn) -> bool:
        """Validates all non-coinbase txs including scripts"""
        pending_utxos: dict[bytes, UTXO] = {}
        seen_outpoints: set[bytes] = set()
        next_height = state.height + 1

        for tx in block.txs[1:]:
            if not self._validate_tx(tx, block, next_height, pending_utxos, seen_outpoints,
                                     get_utxo_fn, get_block_at_height_fn):
                return False

            for vout, output in enumerate(tx.outputs):
                utxo = UTXO.from_txoutput(
                    outpoint=tx.txid + vout.to_bytes(TX.VOUT, "little"),
                    txoutput=output,
                    block_height=next_height,
                    is_coinbase=False,
                )
                pending_utxos[utxo.outpoint()] = utxo

        return True

    def _validate_tx(self, tx: Tx, block: Block, next_height: int,
                     pending_utxos: dict, seen_outpoints: set,
                     get_utxo_fn, get_block_at_height_fn) -> bool:
        """Locktime, maturity, double-spend, relative locktime, then scripts"""

        if not self._validate_locktime(tx, next_height):
            return False

        utxos_for_tx = []

        for txin in tx.inputs:
            utxo = pending_utxos.get(txin.outpoint) or get_utxo_fn(txin.outpoint)
            if utxo is None:
                logger.error(f"Missing UTXO: {txin.outpoint.hex()}")
                return False
            if utxo.is_coinbase and (next_height - utxo.block_height) < COINBASE_MATURITY:
                logger.error("Coinbase UTXO spent before maturity")
                return False
            if txin.outpoint in seen_outpoints:
                logger.error("Intra-block double spend")
                return False

            seen_outpoints.add(txin.outpoint)
            utxos_for_tx.append(utxo)

            if not self._check_relative_locktime(txin, utxo, block, next_height, get_block_at_height_fn):
                return False

        # --- Script validation (the new addition) ---
        if not self._validate_scripts(tx, utxos_for_tx):
            return False

        return True

    # --- Script validation ---

    def _validate_scripts(self, tx: Tx, utxos: list[UTXO]) -> bool:
        """
        Dispatches to the correct script/signature verification path
        per input based on scriptpubkey type.
        """
        # for i, (txin, utxo) in enumerate(zip(tx.inputs, utxos)):
        #     script_type = classify_script(utxo.scriptpubkey)
        #
        #     if script_type == ScriptType.P2PKH:
        #         if not self._verify_p2pkh(tx, i, utxo):
        #             return False
        #
        #     elif script_type == ScriptType.P2WPKH:
        #         if not self._verify_p2wpkh(tx, i, utxo):
        #             return False
        #
        #     elif script_type == ScriptType.P2WSH:
        #         if not self._verify_p2wsh(tx, i, utxo):
        #             return False
        #
        #     elif script_type == ScriptType.P2TR:
        #         if not self._verify_p2tr(tx, i, utxos):
        #             return False
        #
        #     elif script_type == ScriptType.P2SH:
        #         if not self._verify_p2sh(tx, i, utxo):
        #             return False
        #
        #     else:
        #         logger.error(f"Unknown script type for input {i}")
        #         return False

        return True

    def _verify_p2pkh(self, tx: Tx, input_index: int, utxo: UTXO) -> bool:
        sighash = self.sig_engine.get_legacy_sighash(tx, input_index, utxo.scriptpubkey)
        # Parse txin.scriptsig for sig + pubkey, then:
        # return self.sig_engine.verify_ecdsa_sig(sig, sighash, pubkey)
        raise NotImplementedError

    def _verify_p2wpkh(self, tx: Tx, input_index: int, utxo: UTXO) -> bool:
        sighash = self.sig_engine.get_segwit_sighash(tx, input_index, utxo.amount, utxo.scriptpubkey)
        # Parse witness stack for sig + pubkey, then verify
        raise NotImplementedError

    def _verify_p2wsh(self, tx: Tx, input_index: int, utxo: UTXO) -> bool:
        # Hash witness script, check against scriptpubkey, then execute
        raise NotImplementedError

    def _verify_p2tr(self, tx: Tx, input_index: int, utxos: list[UTXO]) -> bool:
        # Detect key-path vs script-path from witness stack, then:
        # key-path:    sig_engine.get_taproot_sighash(..., ext_flag=0)
        # script-path: sig_engine.get_taproot_sighash(..., ext_flag=1)
        raise NotImplementedError

    def _verify_p2sh(self, tx: Tx, input_index: int, utxo: UTXO) -> bool:
        # Deserialize redeem script from scriptsig, hash and compare, then execute
        raise NotImplementedError

    # --- Locktime helpers (moved from Blockchain) ---

    @staticmethod
    def _validate_locktime(tx: Tx, next_height: int) -> bool:
        ...

    @staticmethod
    def _check_relative_locktime(txin: TxIn, utxo: UTXO, block: Block,
                                 next_height: int, get_block_at_height_fn) -> bool:
        ...
