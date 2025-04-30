"""
Class for the ScriptEvaluator: High-level API: validates UTXO spends using scriptSig, scriptPubKey, and possibly witness
"""

from src.crypto import hash160, sha256
from src.db import BitCloneDatabase
from src.logger import get_logger
from src.script.script_engine import ScriptEngine
from src.script.scriptpubkey_factory import ScriptPubKeyFactory
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

        # --- Get ScriptSig and ScriptPubKey
        script_sig = tx.inputs[input_index].script_sig
        script_pubkey = utxo.script_pubkey

        # --- Classify scriptpubkey
        is_p2wpkh = (
                len(script_pubkey) == 22 and
                script_pubkey[0] == 0x00 and
                script_pubkey[1] == 0x14
        )
        is_p2wsh = (
                len(script_pubkey) == 34 and
                script_pubkey[0] == 0x00 and
                script_pubkey[1] == 0x20
        )

        # Handle SegWit inputs
        if script_sig == b'' or script_sig is None:
            if not tx.segwit:
                logger.error("SegWit flag not set on transaction")
                return False

            # --- P2WSH
            if is_p2wsh:
                logger.debug("Handling P2WSH input")
                witness = tx.witnesses[input_index]
                if witness.stackitems < 1:
                    logger.error("P2WSH witness stack is empty")
                    return False

                # Last item = redeem script
                redeem_script = witness.items[-1].item
                redeem_script_hash = sha256(redeem_script)

                # Validate redeem script hash
                if redeem_script_hash != script_pubkey[2:]:
                    logger.error("P2WSH redeem script hash mismatch")
                    return False

                # Set up witness stack
                self.script_engine.clear_stacks()

                # Push witness items (except redeem script) in order
                for item in witness.items[:-1]:
                    self.script_engine.stack.push(item.item)

                return self.script_engine.eval_script(
                    script=redeem_script,
                    tx=tx,
                    input_index=input_index,
                    utxo=utxo,
                    amount=utxo.amount,
                    script_code=redeem_script,
                    clear_stacks=False
                )

            # --- P2WPKH
            elif is_p2wpkh:
                logger.debug("Handling P2WPKH input")

                pubkey_hash = script_pubkey[2:]
                witness = tx.witnesses[input_index]
                if witness.stackitems != 2:
                    logger.error("P2WPKH witness stack should have exactly 2 items")
                    return False

                sig = witness.items[0].item
                pubkey = witness.items[1].item

                # Validate pubkey hash
                if hash160(pubkey) != pubkey_hash:
                    logger.error("P2WPKH pubkey hash mismatch")
                    return False

                # Build implied P2PKH script
                p2pkh_scriptpubkey = ScriptPubKeyFactory.p2pkh(pubkey)
                # pubkey_engine = ScriptPubKeyEngine()
                # script_code = pubkey_engine.p2pkh(pubkey).scriptpubkey

                self.script_engine.clear_stacks()
                self.script_engine.stack.push(sig)
                self.script_engine.stack.push(pubkey)

                return self.script_engine.eval_script(
                    script=p2pkh_scriptpubkey.script,
                    tx=tx,
                    input_index=input_index,
                    utxo=utxo,
                    amount=utxo.amount,
                    script_code=p2pkh_scriptpubkey.script,
                    clear_stacks=False
                )


            else:
                logger.error("Unknown SegWit input type")
                return False

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
