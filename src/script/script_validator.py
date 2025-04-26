"""
Class for the ScriptEvaluator: High-level API: validates UTXO spends using scriptSig, scriptPubKey, and possibly witness
"""

from src.crypto import hash160
from src.db import BitCloneDatabase
from src.logger import get_logger
from src.script.script_engine import ScriptEngine
from src.script.script_pubkey import ScriptPubKeyEngine
from src.tx import Transaction, UTXO

logger = get_logger(__name__)


class ScriptValidator:
    """
    Validates UTXOs
    """

    def __init__(self, db: BitCloneDatabase):
        self.db = db
        self.script_engine = ScriptEngine()

    def validate_utxo(self, tx: Transaction, input_index: int = 0) -> bool:
        """
        Validates input scriptSig + scriptPubKey (and redeemScript if P2SH).
        """
        # --- Get UTXO
        _input = tx.inputs[input_index]
        utxo_tuple = self.db.get_utxo(_input.txid, _input.vout)
        if utxo_tuple is None:
            return False
        utxo = UTXO(*utxo_tuple)

        # --- Get ScriptSig
        script_sig = tx.inputs[input_index].script_sig

        # --- Get ScriptPubKey
        script_pubkey = utxo.script_pubkey

        # --- Check for p2wpkh
        if script_sig == b'' or script_sig is None:
            logger.debug("Handling P2WPKH input")

            if not tx.segwit:
                logger.error("SegWit flag not set on transaction")
                return False

            # Extract pubkey hash from scriptPubKey
            pubkey_hash = script_pubkey[2:]

            # Extract witness items
            witness = tx.witnesses[input_index]
            if witness.stackitems != 2:
                logger.debug("Invalid witness item count for P2WPKH")
                return False

            sig = witness.items[0].item  # Witness.WitnessItem.item
            pubkey = witness.items[1].item

            # Check that pubkey hashes to expected value
            if hash160(pubkey) != pubkey_hash:
                logger.debug("P2WPKH pubkey hash mismatch")
                return False

            # Push witness items to stack
            self.script_engine.clear_stacks()
            self.script_engine.stack.push(sig)
            self.script_engine.stack.push(pubkey)

            # Reconstruct implied script (standard P2PKH)
            pubkey_engine = ScriptPubKeyEngine()
            script_code = pubkey_engine.p2pkh(pubkey).scriptpubkey
            return self.script_engine.eval_script(script_code, tx, input_index, utxo=utxo, amount=utxo.amount,
                                                  clear_stacks=False)

        # --- Step 1: Evaluate scriptSig
        self.script_engine.eval_script(script_sig, tx, input_index, utxo=utxo)
        logger.debug("Stack has evaluated scriptsig")

        # --- Step 2: Check for P2SH
        is_p2sh = (
                len(script_pubkey) == 23 and
                script_pubkey[0] == 0xa9 and  # OP_HASH160
                script_pubkey[1] == 0x14 and  # PUSH 20 bytes
                script_pubkey[-1] == 0x87  # OP_EQUAL
        )

        if not is_p2sh:
            # Evaluate scriptPubKey using resulting stack from scriptSig
            return self.script_engine.eval_script(script_pubkey, tx, input_index, utxo=utxo, clear_stacks=False)

        # --- Step 3: Handle P2SH
        if self.script_engine.stack.height == 0:
            logger.debug("P2SH redeem script missing")
            return False

        redeem_script = self.script_engine.stack.pop()
        # Push redeem_script to be hashed and compared by scriptPubKey
        self.script_engine.stack.push(redeem_script)

        # Evaluate the P2SH scriptPubKey (e.g., OP_HASH160 <20B> OP_EQUAL)
        self.script_engine.eval_script(script_pubkey, tx, input_index, utxo=utxo, clear_stacks=False)

        # Pop top element and verify OP_EQUAL
        op_equal = self.script_engine.stack.pop()
        if not op_equal == b'\x01':
            logger.debug("P2SH ScriptPubKey failed HASH160 verification")
            return False

        # Step 4: Evaluate the redeem script using *current stack*
        return self.script_engine.eval_script(redeem_script, tx, input_index, utxo=utxo, clear_stacks=False)

    def _validate_p2wpk(self, script_sig: bytes, script_pubkey: bytes, tx: Transaction, input_index: int, utxo: UTXO):
        pass
