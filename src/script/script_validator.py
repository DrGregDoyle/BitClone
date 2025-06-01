"""
Class for the ScriptEvaluator: High-level API: validates UTXO spends using scriptSig, scriptPubKey, and possibly witness
"""

from src.crypto import hash160, sha256, tagged_hash_function, HashType
from src.data import write_compact_size
from src.db import BitCloneDatabase
from src.logger import get_logger
from src.script.script_engine import ScriptEngine
from src.script.script_tree import ScriptTree
from src.script.scriptpubkey_factory import ScriptPubKeyFactory
from src.script.signature_engine import SignatureEngine
from src.tx import Transaction, UTXO

logger = get_logger(__name__)

__all__ = ["ScriptValidator"]


class ScriptValidator:
    """
    Validates UTXOs
    """

    def __init__(self, db: BitCloneDatabase):
        self.db = db
        self.script_engine = ScriptEngine()
        self.signature_engine = SignatureEngine()

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
        is_p2tr = (
                len(script_pubkey) == 34 and
                script_pubkey[0] == 0x51 and  # OP_1
                script_pubkey[1] == 0x20  # OP_PUSH32
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

            # --- P2TR
            elif is_p2tr:
                logger.debug("Handling P2TR input")

                witness = tx.witnesses[input_index]

                # Determine keypath vs script path
                if witness.stackitems == 1:
                    # Key path
                    logger.debug("Handling keypath input")

                    schnorr_sig = witness.items[0].item
                    tweaked_pubkey = script_pubkey[2:]  # x-only pubkey
                    tweaked_pubkey_int = int.from_bytes(tweaked_pubkey, "big")

                    # -- Compute sighash message (Taproot key-path)
                    sighash = self.signature_engine.get_taproot_sighash(
                        tx=tx,
                        input_index=input_index,
                        utxos=[utxo]
                    )

                    # -- Return verify signature
                    return self.signature_engine.verify_schnorr_signature(
                        public_key_x=tweaked_pubkey_int,
                        message=sighash,
                        signature=schnorr_sig
                    )
                else:
                    # Script path
                    logger.debug("Handling Taproot script-path input")
                    # taproot = Taproot()

                    # Parse witness
                    witness_items = witness.items

                    if witness.stackitems < 2:
                        logger.error("Script-path witness must contain at least leaf_script and control_block")
                        return False

                    leaf_script = witness_items[-2].item
                    control_block = witness_items[-1].item
                    script_inputs = [item.item for item in witness_items[:-2]]

                    # Parse control block
                    control_byte = control_block[0]
                    leaf_version = control_byte & 0xfe  # bitwise & operator, 0xfe = 0x1111 1110.
                    parity = control_byte & 0x01  # bitwise & operator, 0x01 = 0x0000 0001
                    internal_key = control_block[1:33]  # xonly_pubkey
                    merkle_path = control_block[33:]  # No merkle path for a single leaft

                    # Compute leaf hash
                    leaf_data = leaf_version.to_bytes(1, "big") + write_compact_size(len(leaf_script)) + leaf_script
                    leaf_hash = tagged_hash_function(leaf_data, b'TapLeaf', HashType.SHA256)

                    # Compute merkle root
                    merkle_root = ScriptTree.eval_merkle_path(leaf_hash, merkle_path)

                    # Compute default extension
                    extension = leaf_hash + b'\x00' + bytes.fromhex("ffffffff")

                    # Compute tweak
                    taptweak_input = internal_key + merkle_root
                    tweak = tagged_hash_function(taptweak_input, b"TapTweak", HashType.SHA256)

                    # Creeate tapscript engine and push inputs
                    tapscript_engine = ScriptEngine(tapscript=True)
                    for i in script_inputs:
                        tapscript_engine.stack.push(i)

                    return tapscript_engine.eval_script(
                        script=leaf_script,
                        tx=tx,
                        input_index=input_index,
                        utxo=utxo,
                        amount=utxo.amount,
                        script_code=extension,
                        clear_stacks=False
                    )

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
