"""
The SignatureEngine class, used to create signatures for transactions
#TODO: Add docstrings to each function stating the algorithm and references
"""

from __future__ import annotations

from enum import IntEnum

from src.core import SignatureError, TX, TAPROOT
from src.cryptography import ecdsa, verify_ecdsa, schnorr_verify, schnorr_sig, hash256, sha256, tapsighash_hash, \
    SECP256K1
from src.data import encode_der_signature, decode_der_signature, write_compact_size, PubKey, get_control_block, \
    Leaf, TweakPubkey, Tree, get_tweak, get_control_byte
from src.script.script_types import P2TR_Key
from src.tx import Transaction, WitnessField, UTXO

__all__ = ["SigHash", "SignatureEngine"]


class SigHash(IntEnum):
    DEFAULT = 0x00
    ALL = 0x01
    NONE = 0x02
    SINGLE = 0x03
    ALL_ANYONECANPAY = 0x81  # (0x81 interpreted as signed int)
    NONE_ANYONECANPAY = 0x82  # (0x82 interpreted as signed int)
    SINGLE_ANYONECANPAY = 0x83  # (0x83 interpreted as signed int)

    def to_byte(self) -> bytes:
        """
        Encodes the sighash integer using Bitcoin numeric encoding
        """
        return self.value.to_bytes(1, "little")

    def for_hashing(self):
        """
        Encodes the sighash integer using BTCNum encoding and padded to 4 bytes
        """
        return self.value.to_bytes(4, "little")


class SignatureEngine:
    """Pure cryptographic operations for signatures"""

    # --- SIGHASH ALGORITHMS --- #

    def get_legacy_sighash(self, tx: Transaction, input_index: int, scriptpubkey: bytes, sighash_num: int = 1):
        """
        Computes legacy message_hash for signing:
            1. Remove all existing script_sigs
            2. Put the script_pubkey from referenced output in the script_sig for the input.
            3. Append the sighash byte(s) at the end of the serialized tx data
            4. Hash the serialized tx data
        We require the following from the SignatureContext:
            script_code == scriptpubkey

        """
        # Verify
        if any(t is None for t in [tx, input_index, sighash_num, scriptpubkey]):
            raise SignatureError("Insufficient context items for legacy signature hash")

        # Get tx_copy
        # tx_copy = Transaction.from_bytes(tx.to_bytes())
        tx_copy = tx.clone()

        # 1, Remove all existing scriptsigs
        for i in tx_copy.inputs:
            i.scriptsig = bytes()

        # 2. Put scriptpubkey in the scriptsig for the input
        tx_copy.inputs[input_index].scriptsig = scriptpubkey

        # 3. Append the sighash byte at the end of the serialized tx data
        sighash = SigHash(sighash_num)
        data = tx_copy.to_bytes() + sighash.for_hashing()

        # 4. Return sighash
        return hash256(data)

    def get_segwit_sighash(self, tx: Transaction, input_index: int, amount: int, scriptpubkey: bytes, sighash_num:
    int = 1):
        """
        We return the sighash for a segwit Transaction
        """
        # 1. Get copy of tx
        tx_copy = Transaction.from_bytes(tx.to_bytes())

        # 2. Construct the preimage and preimage hash
        # 2-1. version
        serialized_version = tx_copy.version.to_bytes(TX.VERSION, "little")

        # 2-2. hash256(serialized txid+vout for all the inputs in the tx)
        serialized_inputs = b''.join([txin.outpoint for txin in tx_copy.inputs])
        hashed_inputs = hash256(serialized_inputs)

        # 2-3. Serialize and hash the sequence of each input
        serialized_sequences = b''.join([txin.sequence.to_bytes(TX.SEQUENCE, "little") for txin in tx_copy.inputs])
        hashed_sequences = hash256(serialized_sequences)

        # 2-4. Serialize the outpoint for the input we're signing
        my_input = tx_copy.inputs[input_index]
        my_input_outpoint = my_input.outpoint

        # 2-5. Create script for the input we're signing
        scriptcode = scriptpubkey  # Either P2WPKH or P2WSH. The latter is a witness script, the former is P2PKH

        # 2-6. Amount
        serialized_amount = amount.to_bytes(TX.AMOUNT, "little")

        # 2-7. My Sequence
        my_sequence = my_input.sequence.to_bytes(TX.SEQUENCE, "little")

        # 2-8. Serialized and hash all outputs
        serialized_outputs = b''.join([txout.to_bytes() for txout in tx_copy.outputs])
        hashed_outputs = hash256(serialized_outputs)

        # 2-9. Locktime
        serialized_locktime = tx_copy.locktime.to_bytes(TX.LOCKTIME, "little")

        # 2.10 Construct pre-image
        preimage = (
                serialized_version + hashed_inputs + hashed_sequences + my_input_outpoint + scriptcode +
                serialized_amount + my_sequence + hashed_outputs + serialized_locktime
        )

        # 2-11. Add signature hash type
        preimage_sighash = preimage + SigHash(sighash_num).for_hashing()

        # # --- LOGGING --- #
        # print(" --- SEGWIT SIGHASH ---")
        # print("---" * 80)
        # print(f"VERSION: {serialized_version.hex()}")
        # print(f"HASHED INPUTS: {hashed_inputs.hex()}")
        # print(f"HASHED SEQUENCES: {hashed_sequences.hex()}")
        # print(f"INPUT: {my_input_outpoint.hex()}")
        # print(f"SCRIPTCODE: {scriptcode.hex()}")
        # print(f"AMOUNT: {serialized_amount.hex()}")
        # print(f"SEQUENCE: {my_sequence.hex()}")
        # print(f"HASHED OUTPUTS: {hashed_outputs.hex()}")
        # print(f"LOCKTIME: {serialized_locktime.hex()}")
        # Return hash of pre-image
        return hash256(preimage_sighash)

    def get_taproot_sighash(self,
                            tx: Transaction,
                            input_index: int,
                            utxos: list[UTXO],  # List of UTXOs for ALL inputs in order
                            ext_flag: int = 0,
                            sighash_num: int = 1,
                            annex: bytes = None,
                            leaf_hash: bytes = None,  # Necesary for script-path spend
                            codesep_pos: bytes = bytes.fromhex("ffffffff")):
        """
        We return the taproot sighash for any type of taproot spend

        NOTE: We expect the list of utxos to correspond to the list of inputs in the tx
        """
        # Copy tx
        tx_copy = Transaction.from_bytes(tx.to_bytes())

        #  Get elements for pre-image
        hash_type = SigHash(sighash_num)
        hash_byte = hash_type.to_byte()
        version = tx_copy.version.to_bytes(TX.VERSION, "little")
        locktime = tx_copy.locktime.to_bytes(TX.LOCKTIME, "little")

        # --- TX ELEMENTS --- #
        _prevouts = b''.join([txin.outpoint for txin in tx_copy.inputs])
        _sequences = b''.join([txin.sequence.to_bytes(TX.SEQUENCE, "little") for txin in tx_copy.inputs])
        _outputs = b''.join([txout.to_bytes() for txout in tx_copy.outputs])

        # 1. Get context elements
        if ext_flag == 1:
            # Script-path spend
            amounts = [u.amount for u in utxos]
            scriptpubkeys = [u.scriptpubkey for u in utxos]
            _amounts = b''.join([a.to_bytes(TX.AMOUNT, "little") for a in amounts])
            _pubkeys = b''.join([write_compact_size(len(pubkey)) + pubkey for pubkey in scriptpubkeys])

        else:
            # Key-path spend
            utxo = utxos[0]
            amount = utxo.amount
            scriptpubkey = utxo.scriptpubkey
            _amounts = amount.to_bytes(TX.AMOUNT, "little")
            _pubkeys = write_compact_size(len(scriptpubkey)) + scriptpubkey

        # --- HASHING --- #
        hash_prevouts = sha256(_prevouts)
        hash_amounts = sha256(_amounts)
        hash_pubkeys = sha256(_pubkeys)
        hash_outputs = sha256(_outputs)
        hash_sequences = sha256(_sequences)

        spend_type_int = (2 * ext_flag) + (1 if annex else 0)
        spend_type = spend_type_int.to_bytes(1, "little")

        # Input specific
        temp_input = tx_copy.inputs[input_index]
        temp_utxo = utxos[input_index]
        input_outpoint = temp_input.outpoint
        input_amount = temp_utxo.amount.to_bytes(TX.AMOUNT, "little")  # From signature Context
        input_scriptpubkey = temp_utxo.scriptpubkey
        input_sequence = temp_input.sequence.to_bytes(TX.SEQUENCE, "little")
        input_index_bytes = input_index.to_bytes(TX.INDEX, "little")

        hash_annex = b''
        if annex:
            hash_annex = sha256(
                write_compact_size(len(annex)) + annex
            )

        hash_single_output = sha256(tx_copy.outputs[input_index].to_bytes())

        # 3. Assemble message for TapSighash hash function
        message = hash_byte + version + locktime

        if hash_type not in [SigHash.ALL_ANYONECANPAY, SigHash.NONE_ANYONECANPAY, SigHash.SINGLE_ANYONECANPAY]:
            # Not an ANYONECANPAY Sighash
            message += hash_prevouts + hash_amounts + hash_pubkeys + hash_sequences

            # Sighash.ALL
            if hash_type == SigHash.ALL:
                message += hash_outputs

            # Spend type and annex
            message += spend_type + input_index_bytes + hash_annex

            # Sighash.SINGLE
            if hash_type == SigHash.SINGLE:
                message += hash_single_output
        else:
            # ANYONECANPAY
            message += spend_type + input_outpoint + input_amount + input_scriptpubkey + input_sequence + hash_annex

        # Get sighash_epoch and create extension if necessary
        extension = b''
        if ext_flag:
            # leaf_hash = ctx.merkle_root if ctx.leaf_hash is None else ctx.leaf_hash
            extension = leaf_hash + TAPROOT.PUBKEY_VERSION + codesep_pos

        sighash_epoch = TAPROOT.SIGHASH_EPOCH

        # # --- TESTING
        # print(f"SHA PREVOUTS: {hash_prevouts.hex()}")
        # print(f"SHA AMOUNTS: {hash_amounts.hex()}")
        # print(f"SHA SEQUENCES: {hash_sequences.hex()}")
        # print(f"SHA SCRIPTPUBKEYS: {hash_pubkeys.hex()}")
        # print(f"SHA OUTPUTS: {hash_outputs.hex()}")

        return tapsighash_hash(sighash_epoch + message + extension)

    # --- Schnorr --- #
    def get_schnorr_sig(self, priv_key: int, msg: bytes, aux_bytes: bytes = None) -> bytes:
        # Validation here
        return schnorr_sig(priv_key, msg, aux_bytes)

    def verify_schnorr_sig(self, xonly_pubkey: int | bytes, msg: bytes, sig: bytes) -> bool:
        # Validation here
        return schnorr_verify(xonly_pubkey, msg, sig)

    # --- ECDSA --- #
    def get_ecdsa_sig(self, private_key: int, message: bytes):
        """
        Returns DER-encoded ECDSA signature
        """
        # Validation here
        r, s = ecdsa(private_key, message)
        return encode_der_signature(r, s)

    def verify_ecdsa_sig(self, signature: bytes, message: bytes, public_key: bytes):
        signature_tuple = decode_der_signature(signature)
        pubkey = PubKey.from_bytes(public_key)
        return verify_ecdsa(signature_tuple, message, pubkey.to_point())


# --- TESTING --- #
if __name__ == "__main__":
    curve = SECP256K1
    sep = "---" * 50
    print(sep)
    print(f" --- TAPROOT SIGNATURE TESTING ---")
    print(sep)

    _xonly_pubkey = bytes.fromhex("924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329")
    pubkey_point = PubKey.from_bytes(_xonly_pubkey)
    leaf_scripts = [
        bytes.fromhex("5187"),
        bytes.fromhex("5287"),
        bytes.fromhex("5387"),
        bytes.fromhex("5487"),
        bytes.fromhex("5587")
    ]
    leaves = [Leaf(s) for s in leaf_scripts]
    tree = Tree(leaf_scripts)
    tweak = get_tweak(_xonly_pubkey, tree.merkle_root)
    tweak_pubkey = TweakPubkey(_xonly_pubkey, tree.merkle_root)

    test_p2tr_pubkey = P2TR_Key(_xonly_pubkey, leaf_scripts)

    # --- SPEND
    unsigned_raw_tx = Transaction.from_bytes(bytes.fromhex(
        "02000000000101d7c0aa93d852c70ed440c5295242c2ac06f41c3a2a174b5a5b112cebdf0f7bec0000000000ffffffff01260100000000000016001492b8c3a56fac121ddcdffbc85b02fb9ef681038a0000000000"))

    # --- CREATE CONTROL BLOCK
    controL_byte = get_control_byte(tweak_pubkey.tweaked_pubkey.to_point())
    merkle_path = tree.generate_merkle_path(bytes.fromhex("5387"))
    control_block = get_control_block(_xonly_pubkey, tree.merkle_root, merkle_path)

    # --- CREATE WITNESS
    script_inputs = bytes.fromhex("03")
    script = bytes.fromhex("5387")
    witness = WitnessField(items=[
        script_inputs, script, control_block
    ])

    signed_tx = Transaction.from_bytes(unsigned_raw_tx.to_bytes())
    signed_tx.witness = [witness]

    # --- VALIDATE AGAINST KNOWN TX
    known_tx = Transaction.from_bytes(bytes.fromhex(
        "02000000000101d7c0aa93d852c70ed440c5295242c2ac06f41c3a2a174b5a5b112cebdf0f7bec0000000000ffffffff01260100000000000016001492b8c3a56fac121ddcdffbc85b02fb9ef681038a03010302538781c0924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a33291324300a84045033ec539f60c70d582c48b9acf04150da091694d83171b44ec9bf2c4bf1ca72f7b8538e9df9bdfd3ba4c305ad11587f12bbfafa00d58ad6051d54962df196af2827a86f4bde3cf7d7c1a9dcb6e17f660badefbc892309bb145f00000000"))
    witnesses_agree = known_tx.witness[0] == witness
    txs_agree = known_tx == signed_tx

    # --- LOGGING
    print(f"TREE: {tree.to_json()}")
    print(f"MERKLE ROOT: {tree.merkle_root.hex()}")
    print(f"TWEAK: {tweak.hex()}")
    print(f"TWEAK PUBKEY: {tweak_pubkey.tweaked_pubkey.x_bytes().hex()}")
    print(f"SCRIPT PUBKEY: {test_p2tr_pubkey.to_json()}")
    print(sep)
    print("--- SPEND ---")
    print(sep)
    print(f"UNSIGNED TX: {unsigned_raw_tx.to_json()}")
    print(f"CONTROL BYTE: {controL_byte.hex()}")
    print(f"MERKLE PATH: {merkle_path.hex()}")
    print(f"CONTROL BLOCK: {control_block.hex()}")
    print(f"WITNESS: {witness.to_json()}")
    print(f"SIGNED TX: {signed_tx.to_json()}")
    print(sep)
    print(" --- VALIDATION --- ")
    print(sep)
    print(f"WITNESSES AGREE: {witnesses_agree}")
    print(f"TXS AGREE: {txs_agree}")
    print(sep)
    print(f"KNOWN TX: {known_tx.to_json()}")
    print(f"TX INPUTS AGREE: {known_tx.inputs[0] == signed_tx.inputs[0]}")
    print(f"TX OUTS AGREE: {known_tx.outputs[0] == signed_tx.outputs[0]}")
    print(f"UNSIGNED OUTPUTS:{unsigned_raw_tx.outputs[0].to_json()}")
