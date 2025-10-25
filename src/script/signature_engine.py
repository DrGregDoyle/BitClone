"""
The SignatureEngine class, used to create signatures for transactions
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

from src.core import SignatureError, TX
from src.cryptography import ecdsa, verify_ecdsa, schnorr_verify, schnorr_sig, hash256
from src.data import encode_der_signature, decode_der_signature
from src.data.ecc_keys import PubKey
from src.script.script_type import ScriptType
from src.script.scriptsig import P2PK_Sig, P2PKH_Sig, P2MS_Sig
from src.tx import Transaction, TxInput, TxOutput, WitnessField


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


@dataclass(slots=True)
class SignatureContext:
    """Holds all data needed to compute a signature hash for a specific input."""
    # Always needed
    tx: "Transaction"
    input_index: int
    sighash_type: int = SigHash.ALL

    # Legacy / SegWit v0
    script_code: Optional[bytes] = None  # scriptpubkey for legacy; witness script for v0
    amount: Optional[int] = None  # satoshis (required for v0 and Taproot)

    # Taproot (BIP341/342)
    ext_flag: int = 0  # 0=key-path, 1=script-path
    annex: Optional[bytes] = None  # must start with 0x50 if present
    tapleaf_script: Optional[bytes] = None  # raw leaf script if script-path
    leaf_version: int = 0xC0  # tapscript v0 default
    codeseparator_pos: int = -1  # -1 if none (BIP342)

    # Optional caches (pass precomputed hashes to avoid recompute)
    prevouts_hash: Optional[bytes] = None
    sequences_hash: Optional[bytes] = None
    outputs_hash: Optional[bytes] = None


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
            sighash_num: int = 1,
            nonce: int = None
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
        # tx = Transaction.from_bytes(ctx.tx.to_bytes())  # Create copy of tx
        input_index = ctx.input_index
        pubkeyhash = ctx.script_code
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
        # Script = OP_PUSHBYTES_25 + OP_DUP + OP_HASH160 + OP_PUSHBYTES_20 + pubkeyhash + OP_EQUALVERIFY + OP_CHECKSIG
        scriptcode = b'\x19\x76\xa9\x14' + pubkeyhash + b'\x88\xac'

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
        pass

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
    version = int.from_bytes(bytes.fromhex("01000000"), "little")
    test_input = TxInput(
        bytes.fromhex("b7994a0db2f373a29227e1d90da883c6ce1cb0dd2d6812e4558041ebbbcfa54b"),  # txid
        0,  # vout
        scriptsig=b'',
        sequence=bytes.fromhex("ffffffff")
    )
    test_output = TxOutput(
        amount=bytes.fromhex("983a000000000000"),
        scriptpubkey=bytes.fromhex("76a914b3e2819b6262e0b1f19fc7229d75677f347c91ac88ac")
    )
    test_tx = Transaction(inputs=[test_input], outputs=[test_output], version=version, locktime=0)
    _sighash_num = 1
    _scriptpubkey = bytes.fromhex("76a9144299ff317fcd12ef19047df66d72454691797bfc88ac")
    _ctx = SignatureContext(tx=test_tx, input_index=0, sighash_type=_sighash_num, script_code=_scriptpubkey)

    engine = SignatureEngine()

    _privkey = int.from_bytes(bytes.fromhex("f94a840f1e1a901843a75dd07ffcc5c84478dc4f987797474c9393ac53ab55e6"), "big")

    print(f"TEST TX BEFORE SIGNING: {test_tx.to_json()}")

    # new_tx = engine.sign_p2pk(test_tx, input_index=0, privkey=_privkey, scriptpubkey=_scriptpubkey)
    # print(f"TEST TX AFTER SIGNING: {new_tx.to_json()}")
