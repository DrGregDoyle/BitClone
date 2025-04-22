"""
The TxEngine class - Used for signing a transaction

NOTES:
    - Signatures are designed with an output in mind. They are designed to unlock an output.
    - Hence a legacy, segwit or taproot signature will be used depending ont the type of output referenced.
"""

from src.crypto import ecdsa, hash256
from src.data import write_compact_size, to_little_bytes, compress_public_key, encode_der_signature
from src.db import BitCloneDatabase
from src.logger import get_logger
from src.script.sighash import SigHash
from src.tx import Transaction, Input, WitnessItem, Witness, UTXO

logger = get_logger(__name__)


class SignatureEngine:
    """
    A class used to sign inputs.
    """
    PUBLICKEY_BYTES = 32

    def __init__(self, db: BitCloneDatabase):
        self.db = db

    def get_legacy_sig(self, private_key: int, tx: Transaction, input_index=0, sighash: SigHash = SigHash.ALL) -> bytes:
        """
        Given a private key, transaction with input to be signed, and corresponding input_index, we return the
        signature for use in the scriptsig for the input.

        Legacy Signing Algorithm:
        --
            1. Remove all existing script_sigs
            2. Put the script_pubkey from referenced output in the script_sig for the input.
            3. Append the sighash byte(s) at the end of the serialized tx data
            4. Hash the serialized tx data
            5. Sign the hashed data using ECDSA
            6. DER encode the signature
            7. Append the sighash byte and return

        """

        # Create copy to not modify original
        tx_copy = Transaction.from_bytes(tx.to_bytes())

        # Testing helper
        # def test_state(log_state: str, test_tx: Transaction = tx_copy):
        #     logger.debug(log_state)
        #     logger.debug(test_tx.to_json())

        # test_state("TX COPY")  # Initial copy state before modifications

        # Step 1: Remove existing script_sigs
        tx_copy = self._remove_scriptsig(tx_copy)
        # test_state("REMOVE SCRIPTSIG")

        # Step 2: Insert the script_pubkey from the referenced UTXO into the input's script_sig
        ref_input = tx_copy.inputs[input_index]
        ref_utxo = self.db.get_utxo(txid=ref_input.txid, vout=ref_input.vout)

        if not ref_utxo:
            raise ValueError("Referenced UTXO not found.")

        r_txid, r_vout, r_amount, r_script_pubkey, r_spent = ref_utxo
        ref_input.script_sig = bytes(r_script_pubkey)
        ref_input.script_sig_size = write_compact_size(len(ref_input.script_sig))
        # test_state("ADD SCRIPT SIG (script_pubkey as placeholder)")

        # print(f"TX ENGINE TX BEFORE HASHING: {tx_copy.to_json()}")

        # Step 3: Get sighash tx data for hashing
        tx_sighash_data = tx_copy.to_bytes() + sighash.for_hashing()
        # logger.debug("SIGHASH TX DATA")
        # logger.debug(f"TYPE: {type(tx_sighash_data)}")
        # logger.debug(f"{tx_sighash_data.hex()}")

        # Step 4: Hash the tx_sighash_data
        hashed_tx_data = hash256(tx_sighash_data)
        # logger.debug(f"HASHED TX DATA")
        # logger.debug(f"TYPE: {type(hashed_tx_data)}")
        # logger.debug(f"{hashed_tx_data.hex()}")

        # Step 5: Sign the hashed_tx_data using ECDSA (uses low-s value)
        (r, s) = ecdsa(private_key, hashed_tx_data)
        # logger.debug(f"ECDSA TUPLE")
        # logger.debug(f"(R,S) = {(r, s)}")

        # Step 6: DER encode the signature
        serialized_signature = encode_der_signature(r, s)

        # Step 7: Append sighash byte and return for use in script sig
        serialized_signature = serialized_signature + sighash.to_byte()
        # logger.debug(f"SIGNATURE: {serialized_signature.hex()}")
        return serialized_signature

    def get_segwit_sig(self, private_key: int, tx: Transaction, input_amount: int, input_index=0, nonce: int = 0,
                       sighash: SigHash = SigHash.ALL) -> Transaction:
        """
        Given a private key, transaction with input to be signed, and corresponding input_index, we return the
        transaction with the signed Witness item

        NB: nonce is used for testing. TODO: Remove once testing complete. Use a random nonce each time

        Segwit Signing Algorithm:
        --
            1. Construct the preimage and preimage hash
                - Grab the version field (reusable)
                - Serialize and hash the txids and vouts for the inputs (reusable)
                - Serialize and hash the sequences for the inputs (reusable)
                - Serialize the txid + vout for the input we're signing (not reusable)
                - Create a scriptcode for the input we're signing (not reusable)
                - Get the sequence for the input we're signing (not reusable)
                - Serialize and hash all the outputs (reusable)
                - Grab the locktime
                - preimage = version + hash256(inputs) + hash256(sequences) + input_outpoint + scriptcode + amount +
                    sequence + hash256(outputs) + locktime
            2. Sign the preimage hash
            3. DER encode the signature
            4. Append signature hash to DER encoding
            5. Construct Witness for corresponding input
            6. Insert Witness into proper spot in witness list and return tx

        """
        # 1. Get preimage hash
        preimage = self.segwit_preimage(tx, input_index, input_amount, sighash)
        preimage_hash = hash256(preimage)
        print(f"TX ENGINE PREIMAGE HASH: {preimage_hash.hex()}")

        # 2. Sign the preimage hash
        r, s = ecdsa(private_key, preimage_hash)

        # 3. DER encode the signature
        der_encoded_sig = encode_der_signature(r, s)

        # 4. Append sighash byte
        serialized_sig = der_encoded_sig + sighash.to_byte()

        # Construct Witness for signature and compressed public key
        item1 = WitnessItem(serialized_sig)
        item2 = WitnessItem(compress_public_key(private_key))
        ref_witness = Witness([item1, item2])
        print(f"REF WITNESS: {ref_witness.to_json()}")

        # Add Witness to witness position in tx
        if not tx.witnesses:
            tx.witnesses = [ref_witness]
        else:
            tx.witnesses[input_index] = ref_witness
        return tx

    def _remove_scriptsig(self, tx: Transaction) -> Transaction:
        # Remove all scriptsigs from the inputs
        for i in tx.inputs:
            i.script_sig = bytes()
            i.script_sig_size = write_compact_size(0)
        return tx

    def segwit_preimage(self, tx: Transaction, input_index: int, amount: int, sighash: SigHash = SigHash.ALL):
        """
        We obtrain the segwit pre-image using the following formula:
            version + hash256(inputs) + hash256(sequences) + input + scriptcode + amount + sequence + hash256(
            outputs) + locktime
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

        # scriptcode
        utxo_row = self.db.get_utxo(temp_input.txid, temp_input.vout)
        utxo = UTXO(*utxo_row)
        scriptcode_pubkey = utxo.script_pubkey
        # print(f"SEGWIT UTXO SCRIPTPUBKEY: {scriptcode_pubkey.hex()}")

        # scriptcode = OP_PUSHBYTES_25 OP_DUP OP_HASH160 OP_PUSHBYTES_20 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
        if scriptcode_pubkey[0] != 0x00 or scriptcode_pubkey[1] != 0x14:
            raise ValueError("ScriptPubKey is not a P2WPKH format")

        pubkeyhash = scriptcode_pubkey[2:]
        scriptcode = b'\x19\x76\xa9\x14' + pubkeyhash + b'\x88\xac'  # 0x19 = length 25

        # amount
        amount = to_little_bytes(amount, Transaction.AMOUNT_BYTES)

        # sequence
        sequence = to_little_bytes(temp_input.sequence, Input.SEQ_BYTES)

        # hash256(outputs)
        outputs = b''.join([txout.to_bytes() for txout in tx.outputs])
        hashed_outputs = hash256(outputs)

        # locktime
        locktime = to_little_bytes(tx.locktime, Transaction.LOCKTIME_BYTES)

        return (
                version + hashed_inputs + hashed_sequences + tx_input + scriptcode + amount + sequence +
                hashed_outputs +
                locktime + sighash.for_hashing())
