"""
The TxEngine class - Used for signing a transaction

NOTES:
    - Signatures are designed with an output in mind. They are designed to unlock an output.
    - Hence a legacy, segwit or taproot signature will be used depending ont the type of output referenced.
"""

from src.crypto import hash256, ecdsa, verify_ecdsa
from src.data import write_compact_size, encode_der_signature, to_little_bytes, get_public_key_point, \
    decode_der_signature
from src.logger import get_logger
from src.script.sighash import SigHash
from src.tx import Transaction, Input

logger = get_logger(__name__)


class SignatureEngine:
    """
    A class used to sign inputs, and construct message hashes for signing
    """
    PUBLICKEY_BYTES = 32

    # --- Utility functions
    def _remove_scriptsig(self, tx: Transaction) -> Transaction:
        # Remove all scriptsigs from the inputs
        for i in tx.inputs:
            i.script_sig = bytes()
            i.script_sig_size = write_compact_size(0)
        return tx

    # --- SigHash construction
    def get_legacy_sighash(self, tx: Transaction, input_index: int, script_pubkey: bytes, sighash_flag: int) -> bytes:
        """
        Computes legacy message_hash for signing:
            1. Remove all existing script_sigs
            2. Put the script_pubkey from referenced output in the script_sig for the input.
            3. Append the sighash byte(s) at the end of the serialized tx data
            4. Hash the serialized tx data
        """
        # Create tx_copy
        tx_copy = Transaction.from_bytes(tx.to_bytes())

        # 1. Remove all existing script_sigs
        tx_copy = self._remove_scriptsig(tx_copy)

        # 2. Insert script_pubkey into input
        tx_copy.inputs[input_index].script_pubkey = script_pubkey
        tx_copy.inputs[input_index].script_sig_size = write_compact_size(len(script_pubkey))

        #  3. Append the sighash byte(s) at the end of the serialized tx data
        sighash = SigHash(sighash_flag)
        data = tx_copy.to_bytes() + sighash.for_hashing()

        # 4. Return message hash
        return hash256(data)

    def get_segwit_sighash(self, tx: Transaction, input_index: int, script_code: bytes, amount: int, sighash_flag:
    int) -> bytes:
        """
        We obtrain the segwit pre-image using the following formula:
            version + hash256(inputs) + hash256(sequences) + input + scriptcode + amount + sequence + hash256(outputs) 
            + locktime + sighash
        We then return the hash256 value of this pre-image
        """

        def encode_outpoint(_input: Input):
            return _input.txid + to_little_bytes(_input.vout, Input.VOUT_BYTES)

        # Version
        version = to_little_bytes(tx.version, Transaction.VERSION_BYTES)

        # hash256(inputs)
        inputs = b''.join([encode_outpoint(txin) for txin in tx.inputs])
        hashed_inputs = hash256(inputs)

        # hash256(sequences)
        sequences = b''.join([to_little_bytes(txin.sequence, Input.SEQ_BYTES) for txin in tx.inputs])
        hashed_sequences = hash256(sequences)

        # input
        temp_input = tx.inputs[input_index]
        tx_input = encode_outpoint(temp_input)

        # amount
        amount = to_little_bytes(amount, Transaction.AMOUNT_BYTES)

        # sequence
        sequence = to_little_bytes(temp_input.sequence, Input.SEQ_BYTES)

        # hash256(outputs)
        outputs = b''.join([txout.to_bytes() for txout in tx.outputs])
        hashed_outputs = hash256(outputs)

        # locktime
        locktime = to_little_bytes(tx.locktime, Transaction.LOCKTIME_BYTES)

        # sighash
        sighash = SigHash(sighash_flag)

        # construct message and return message hash
        data = (version + hashed_inputs + hashed_sequences + tx_input + script_code + amount + sequence +
                hashed_outputs + locktime + sighash.for_hashing())
        return hash256(data)

    # --- Sign Message
    def sign_message(self, private_key: int, message_hash: bytes, sighash_flag: int) -> bytes:
        """
        Given a private key, a message hash and a sighash flag, we create a DER-encoded ECDSA signature with attached
        sighash byte
        """
        # Sign the message hash using ECDSA (uses low-s value)
        (r, s) = ecdsa(private_key, message_hash)

        # DER encode the signature
        der_signature = encode_der_signature(r, s)

        # Append sighash byte and return for use in script sig
        return der_signature + SigHash(sighash_flag).to_byte()

    # --- Verify Signature
    def verify_sig(self, signature: bytes, pubkey: bytes, message_hash: bytes) -> bool:
        """
        Given a DER-encoded signature, the pubkey and message hash, we verify the ecdsa signature
        """
        # Get pubkey as integer tuple
        pubkey_point = get_public_key_point(pubkey)

        # Decode DER signature
        sig_tuple = decode_der_signature(signature)

        # Return verification bool
        return verify_ecdsa(sig_tuple, message_hash, pubkey_point)
