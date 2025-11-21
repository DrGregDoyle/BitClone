"""
The SignatureEngine class, used to create signatures for transactions
#TODO: Add docstrings to each function stating the algorithm and references
"""

from __future__ import annotations

from enum import IntEnum
from typing import Optional

from src.core import SignatureError, TX, TAPROOT
from src.cryptography import ecdsa, verify_ecdsa, schnorr_verify, schnorr_sig, hash256, sha256, tapsighash_hash, \
    SECP256K1
from src.data import encode_der_signature, decode_der_signature, write_compact_size, PubKey, get_control_block, \
    get_unbalanced_merkle_root, Leaf, TweakPubkey, Tree, get_tweak
from src.script.context import SignatureContext
from src.script.script_type import ScriptType
from src.script.scriptpubkey import P2TR_Key
from src.script.scriptsig import P2PK_Sig, P2PKH_Sig, P2MS_Sig
from src.tx import Transaction, WitnessField

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

    # --- SIGN TRANSACTION TYPES --- #
    def sign_legacy_tx(
            self,
            tx: Transaction,
            input_index: int,
            script_code: bytes,
            script_type: ScriptType,
            sighash_num: int = SigHash.ALL,
            privkey: Optional[int | bytes] = None,
            privkeys: Optional[list[int | bytes]] = None,
            **kwargs
    ) -> Transaction:
        """
        Signs a legacy transaction input and updates the transaction.

        Args:
            tx: The transaction to sign
            input_index: Index of the input being signed
            script_code: The scriptPubKey being spent (or redeem script for P2SH)
            script_type: Type of script (P2PK_Sig, P2PKH_Sig, P2MS, etc.)
            sighash_num: Sighash type
            privkey: Single private key (for P2PK_Sig, P2PKH_Sig)
            privkeys: List of private keys (for P2MS)
            **kwargs: Additional parameters for specific script types
                - pubkey: Public key bytes (optional for P2PKH_Sig, will derive if not provided)

        Returns:
            The transaction with the signed input
        """
        # Validate input
        if script_type == ScriptType.P2MS:
            if privkeys is None or len(privkeys) == 0:
                raise SignatureError("P2MS requires 'privkeys' parameter (list of private keys)")
        else:
            if privkey is None:
                raise SignatureError(f"{script_type} requires 'privkey' parameter")

        # Create signature context
        legacy_ctx = SignatureContext(
            tx=tx,
            input_index=input_index,
            sighash_type=sighash_num,
            script_code=script_code
        )

        # Get the sighash (same for all signatures)
        legacy_sighash = self.get_legacy_sighash(legacy_ctx)

        def create_full_sig(_privkey: int | bytes, _sighash_num: int = 0):
            privkey_int = int.from_bytes(_privkey, "big") if isinstance(_privkey, bytes) else _privkey
            der_sig = self.get_ecdsa_sig(privkey_int, legacy_sighash)
            return der_sig + SigHash(_sighash_num).to_byte()

        # Build scriptsig based on script type
        if script_type == ScriptType.P2PK:
            full_sig = create_full_sig(privkey, sighash_num)
            scriptsig = P2PK_Sig(full_sig).script

        elif script_type == ScriptType.P2PKH:
            full_sig = create_full_sig(privkey, sighash_num)

            # Get pubkey (either provided or derive from privkey)
            pubkey = kwargs.get('pubkey')
            if pubkey is None:
                pubkey = PubKey(privkey).compressed() if isinstance(privkey, int) else PubKey.from_bytes(
                    privkey).compressed()

            scriptsig = P2PKH_Sig(full_sig, pubkey).script

        elif script_type == ScriptType.P2MS:
            # Generate multiple signatures from the same sighash
            signatures = []
            for pk in privkeys:
                full_sig = create_full_sig(pk, sighash_num)
                signatures.append(full_sig)

            scriptsig = P2MS_Sig(signatures).script

        else:
            raise SignatureError(f"Unsupported script type for legacy signing: {script_type}")

        # Update the transaction
        tx.inputs[input_index].scriptsig = scriptsig
        return tx

    def sign_segwit_tx(
            self,
            tx: Transaction,
            input_index: int,
            script_code: bytes,
            amount: int,
            privkey: int | bytes,
            sighash_num: int = 1
    ) -> Transaction:
        """
        The algorithm for signing a segwit transaction
        """
        # Setup
        privkey_int = int.from_bytes(privkey, 'big') if isinstance(privkey, bytes) else privkey

        # Validation
        # TODO: Add validation here

        # Step 1. Construct the preimage hash
        ctx = SignatureContext(
            tx=tx,
            input_index=input_index,
            sighash_type=sighash_num,
            script_code=script_code,
            amount=amount
        )
        preimage_hash = self.get_segwit_sighash(ctx)

        # Step 2. Sign the preimage hash | method returns DER encoded signature
        preimage_sig = self.get_ecdsa_sig(privkey_int, preimage_hash)

        # Step 3. Append sighash type to der_sig
        segwit_sig = preimage_sig + SigHash(sighash_num).to_byte()

        # Step 4. Construct WitnessField = [signature, compressed public key]
        cpk = PubKey(privkey_int).compressed()
        witness_field = WitnessField(items=[segwit_sig, cpk])

        # Step 5. Insert witness into the Tx
        if not tx.witness:
            tx.witness.append(witness_field)
        else:
            tx.witness[input_index] = witness_field
        return tx

    def sign_taproot_keypath(
            self,
            tx: Transaction,
            input_index: int,
            script_code: bytes,
            amount: int,
            privkey: int | bytes,
            sighash_num: int = 1,
            aux_bytes: bytes = None

    ):
        # Create signature context
        ctx = SignatureContext(
            tx=tx,
            input_index=input_index,
            sighash_type=sighash_num,
            script_code=script_code,
            amount=amount,
            annex=None,
            ext_flag=0
        )

        # Get sighash
        taproot_sighash = self.get_taproot_sighash(ctx)
        print(f"TAPROOT SIGHASH: {taproot_sighash.hex()}")

        # Format privkey
        privkey_int = int.from_bytes(privkey, "big") if isinstance(privkey, bytes) else privkey
        print(f"PRIVKEY: {privkey_int.to_bytes(32, 'big').hex()}")

        # Get signature
        keypath_schnorr_sig = self.get_schnorr_sig(privkey_int, taproot_sighash, aux_bytes)
        print(f'SCHNORR SIG: {keypath_schnorr_sig.hex()}')

        # Validate schnorr sig
        temp_pubkey = PubKey(privkey_int)
        valid_sig = self.verify_schnorr_sig(temp_pubkey.x_bytes(), taproot_sighash, keypath_schnorr_sig)
        print(f"VALID SIG: {valid_sig}")

        # Create and add witness item | signature + sighash_byte
        witness_item = keypath_schnorr_sig + SigHash(sighash_num).to_byte()
        keypath_witness = WitnessField(items=[witness_item])

        if tx.witness:
            tx.witness[input_index] = keypath_witness
        else:
            tx.witness.append(keypath_witness)

        # Return tx with withness signature element
        return tx

    def sign_taproot_scriptpath(self, tx: Transaction, input_index: int, privkey: int | bytes, amount: int,
                                xonly_pubkey: bytes, scripts: list[bytes], script_index: int = 0, sighash_type: int = 1,
                                aux_rand: bytes = None) -> Transaction:
        # --- Step 1: Get the P2TR ScriptPubKey and merkle root
        p2tr_key = P2TR_Key(xonly_pubkey=xonly_pubkey, scripts=scripts)
        merkle_root = get_unbalanced_merkle_root(scripts=scripts)

        # --- Step 2: Construct the message sighash
        ctx = SignatureContext(
            tx=tx, input_index=input_index, sighash_type=sighash_type, ext_flag=1, amounts=[amount],
            prev_scriptpubkeys=[p2tr_key.script], amount=amount, merkle_root=merkle_root
        )
        taproot_sighash = self.get_taproot_sighash(ctx)
        print(f"TAPFOOT SIGHASH: {taproot_sighash.hex()}")

        # --- Step 3: Sign the sighash using Schnorr signatures
        privkey_int = int.from_bytes(privkey, "big") if isinstance(privkey, bytes) else privkey
        taproot_sig = self.get_schnorr_sig(privkey_int, taproot_sighash, aux_rand)
        print(f"SIGNATURE: {taproot_sig.hex()}")

        # --- Step 4: Add the hash byte
        taproot_sigand = taproot_sig + SigHash(sighash_type).to_byte()
        print(f"SIGNATURE WITH HASH BYTE: {taproot_sigand.hex()}")

        # --- Step 5: Get merkle path and control block
        if len(scripts) > 1:
            # Todo: Get merkle path here
            merkle_path = b''
        else:
            merkle_path = b''
        control_block = get_control_block(xonly_pubkey, merkle_root, merkle_path)

        # --- Step 6: Get leaf script and create WitnessField
        leaf_script = scripts[script_index]
        witness = WitnessField(items=[taproot_sigand, leaf_script, control_block])
        print(f"WITNESS: {witness.to_json()}")
        print(f"WITNESS SERIALIZED: {witness.to_bytes().hex()}")

        # --- Step 7: Add witness to witness list in tx and return it
        tx.witness[input_index] = witness
        return tx

    # --- SIGHASH ALGORITHMS --- #

    def get_legacy_sighash(self, ctx: SignatureContext):
        """
        Computes legacy message_hash for signing:
            1. Remove all existing script_sigs
            2. Put the script_pubkey from referenced output in the script_sig for the input.
            3. Append the sighash byte(s) at the end of the serialized tx data
            4. Hash the serialized tx data
        We require the following from the SignatureContext:
            script_code == scriptpubkey

        """
        # Get context items
        tx = Transaction.from_bytes(ctx.tx.to_bytes())  # Create copy of tx
        input_index = ctx.input_index
        scriptpubkey = ctx.script_code
        sighash_num = ctx.sighash_type

        # Verify
        if any(t is None for t in [tx, input_index, sighash_num, scriptpubkey]):
            raise SignatureError("Insufficient context items for legacy signature hash")

        # 1, Remove all existing scriptsigs
        for i in tx.inputs:
            i.scriptsig = bytes()

        # 2. Put scriptpubkey in the scriptsig for the input
        tx.inputs[input_index].scriptsig = scriptpubkey

        # 3. Append the sighash byte at the end of the serialized tx data
        sighash = SigHash(sighash_num)
        data = tx.to_bytes() + sighash.for_hashing()

        # 4. Return sighash
        return hash256(data)

    def get_segwit_sighash(self, ctx: SignatureContext):
        """
        """
        # 1. Get tx from context
        # Get context items
        tx = ctx.tx
        input_index = ctx.input_index
        script_code = ctx.script_code
        sighash_num = ctx.sighash_type
        amount = ctx.amount

        # 2. Construct the preimage and preimage hash
        # 2-1. version
        serialized_version = tx.version.to_bytes(TX.VERSION, "little")

        # 2-2. hash256(serialized txid+vout for all the inputs in the tx)
        serialized_inputs = b''.join([txin.outpoint for txin in tx.inputs])
        hashed_inputs = hash256(serialized_inputs)

        # 2-3. Serialize and hash the sequence of each input
        serialized_sequences = b''.join([txin.sequence.to_bytes(TX.SEQUENCE, "little") for txin in tx.inputs])
        hashed_sequences = hash256(serialized_sequences)

        # 2-4. Serialize the outpoint for the input we're signing
        my_input = tx.inputs[input_index]
        my_input_outpoint = my_input.outpoint

        # 2-5. Create script for the input we're signing
        scriptcode = script_code  # Either P2WPKH or P2WSH. The latter is a witness script, the former is P2PKH

        # 2-6. Amount
        serialized_amount = amount.to_bytes(TX.AMOUNT, "little")

        # 2-7. My Sequence
        my_sequence = my_input.sequence.to_bytes(TX.SEQUENCE, "little")

        # 2-8. Serialized and hash all outputs
        serialized_outputs = b''.join([txout.to_bytes() for txout in tx.outputs])
        hashed_outputs = hash256(serialized_outputs)

        # 2-9. Locktime
        serialized_locktime = tx.locktime.to_bytes(TX.LOCKTIME, "little")

        # 2.10 Construct pre-image
        preimage = (
                serialized_version + hashed_inputs + hashed_sequences + my_input_outpoint + scriptcode +
                serialized_amount + my_sequence + hashed_outputs + serialized_locktime
        )

        # 2-11. Add signature hash type
        preimage_sighash = preimage + SigHash(sighash_num).for_hashing()

        # --- LOGGING --- #
        print(" --- SEGWIT SIGHASH ---")
        print("---" * 80)
        print(f"VERSION: {serialized_version.hex()}")
        print(f"HASHED INPUTS: {hashed_inputs.hex()}")
        print(f"HASHED SEQUENCES: {hashed_sequences.hex()}")
        print(f"INPUT: {my_input_outpoint.hex()}")
        print(f"SCRIPTCODE: {scriptcode.hex()}")
        print(f"AMOUNT: {serialized_amount.hex()}")
        print(f"SEQUENCE: {my_sequence.hex()}")
        print(f"HASHED OUTPUTS: {hashed_outputs.hex()}")
        print(f"LOCKTIME: {serialized_locktime.hex()}")
        return hash256(preimage_sighash)

    def get_taproot_sighash(self, ctx: SignatureContext):
        # TODO: Use extension flag to separate into key-path and spend-path
        # 1. Get context elements
        tx = ctx.tx
        input_index = ctx.input_index
        sighash_num = ctx.sighash_type
        scriptpubkey = ctx.script_code
        amount = ctx.amount
        extension_flag = ctx.ext_flag
        annex_val = ctx.annex
        amounts = ctx.amounts  # List of amounts
        pubkeys = ctx.prev_scriptpubkeys  # List of scriptpubkeys

        # 2. Get elements for pre-image
        hash_type = SigHash(sighash_num)
        hash_byte = hash_type.to_byte()
        version = tx.version.to_bytes(TX.VERSION, "little")
        locktime = tx.locktime.to_bytes(TX.LOCKTIME, "little")

        # --- TX ELEMENTS --- #
        _prevouts = b''.join([txin.outpoint for txin in tx.inputs])
        _sequences = b''.join([txin.sequence.to_bytes(TX.SEQUENCE, "little") for txin in tx.inputs])
        _outputs = b''.join([txout.to_bytes() for txout in tx.outputs])

        # Get amounts and pubkeys based on script/key-path spend
        if extension_flag:
            _amounts = b''.join([a.to_bytes(TX.AMOUNT, "little") for a in amounts])
            _pubkeys = b''.join([write_compact_size(len(pubkey)) + pubkey for pubkey in pubkeys])
        else:
            _amounts = amount.to_bytes(TX.AMOUNT, "little")
            _pubkeys = write_compact_size(len(scriptpubkey)) + scriptpubkey

        # --- HASHING --- #
        hash_prevouts = sha256(_prevouts)
        hash_amounts = sha256(_amounts)
        hash_pubkeys = sha256(_pubkeys)
        hash_outputs = sha256(_outputs)
        hash_sequences = sha256(_sequences)

        spend_type_int = (2 * extension_flag) + (1 if annex_val else 0)
        spend_type = spend_type_int.to_bytes(1, "little")

        # Input specific
        temp_input = tx.inputs[input_index]
        input_outpoint = temp_input.outpoint
        input_amount = amount.to_bytes(TX.AMOUNT, "little")  # From signature Context
        input_scriptpubkey = scriptpubkey
        input_sequence = temp_input.sequence.to_bytes(TX.SEQUENCE, "little")
        input_index_bytes = input_index.to_bytes(TX.INDEX, "little")

        hash_annex = b''
        if annex_val:
            hash_annex = sha256(
                write_compact_size(len(annex_val)) + annex_val
            )

        hash_single_output = sha256(tx.outputs[input_index].to_bytes())

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
        if extension_flag:
            leaf_hash = ctx.merkle_root if ctx.leaf_hash is None else ctx.leaf_hash
            extension = leaf_hash + ctx.pubkey_version + ctx.codesep_pos

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

    xonly_pubkey = bytes.fromhex("924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329")
    pubkey_point = PubKey.from_bytes(xonly_pubkey)
    leaf_scripts = [
        bytes.fromhex("5187"),
        bytes.fromhex("5287"),
        bytes.fromhex("5387"),
        bytes.fromhex("5487"),
        bytes.fromhex("5587")
    ]
    leaves = [Leaf(s) for s in leaf_scripts]
    tree = Tree(leaf_scripts)
    tweak = get_tweak(xonly_pubkey, tree.merkle_root)
    tweak_pubkey = TweakPubkey(xonly_pubkey, tree.merkle_root)

    test_p2tr_pubkey = P2TR_Key(xonly_pubkey, leaf_scripts)

    # --- SPEND
    unsigned_raw_tx = Transaction.from_bytes(bytes.fromhex(
        "02000000000101d7c0aa93d852c70ed440c5295242c2ac06f41c3a2a174b5a5b112cebdf0f7bec0000000000ffffffff014c1d0000000000001600140de745dc58d8e62e6f47bde30cd5804a82016f9e0000000000"))

    # script_input = bytes.fromhex("03")
    # leaf_script = bytes.fromhex("5387")
    # control_byte = get_control_byte(pubkey_point)
    # merkle_path = bytes.fromhex(
    #     "1324300a84045033ec539f60c70d582c48b9acf04150da091694d83171b44ec9bf2c4bf1ca72f7b8538e9df9bdfd3ba4c305ad11587f12bbfafa00d58ad6051d54962df196af2827a86f4bde3cf7d7c1a9dcb6e17f660badefbc892309bb145f")
    # merkle_root = tree.merkle_root
    # control_block = get_control_block(xonly_pubkey, merkle_root, merkle_path)
    #
    # constructed_witness = WitnessField(items=[
    #     script_input, leaf_script, control_block
    # ])

    # known_tx = Transaction.from_bytes(bytes.fromhex(
    #     "02000000000101d7c0aa93d852c70ed440c5295242c2ac06f41c3a2a174b5a5b112cebdf0f7bec0000000000ffffffff01260100000000000016001492b8c3a56fac121ddcdffbc85b02fb9ef681038a03010302538781c0924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a33291324300a84045033ec539f60c70d582c48b9acf04150da091694d83171b44ec9bf2c4bf1ca72f7b8538e9df9bdfd3ba4c305ad11587f12bbfafa00d58ad6051d54962df196af2827a86f4bde3cf7d7c1a9dcb6e17f660badefbc892309bb145f00000000"))

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
    # print(f"CONTROL BYTE: {control_byte.hex()}")
    # print(f"PUBKEY: {xonly_pubkey.hex()}")
    # print(f"CONTROL BLOCK: {control_block.hex()}")
    # print(f"CONSTRUCTED WITNESS: {constructed_witness.to_json()}")
    # print(f"KNOWN TX: {known_tx.to_json()}")
    # print(f"WITNESSES AGREE: {constructed_witness == known_tx.witness[0]}")
