"""
The TxEngine class - Used for signing a transaction
"""

from enum import IntEnum

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from src.crypto.ecdsa import ecdsa
from src.crypto.hash_functions import hash256
from src.data.data_handling import write_compact_size, to_little_bytes
from src.db import BitCloneDatabase
from src.logger import get_logger
from src.script.stack import BTCNum
from src.tx import Transaction, Output, Input

logger = get_logger(__name__)


class SigHash(IntEnum):
    ALL = 1
    NONE = 2
    SINGLE = 3
    ALL_ANYONECANPAY = -127  # (0x81 interpreted as signed int)
    NONE_ANYONECANPAY = -126  # (0x82 interpreted as signed int)
    SINGLE_ANYONECANPAY = -125  # (0x83 interpreted as signed int)

    def to_byte(self) -> bytes:
        """
        Encodes the sighash integer using Bitcoin numeric encoding (BTCNum).
        """
        btc_num = BTCNum(int(self.value))
        return btc_num.bytes


class TxEngine:

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
        def test_state(log_state: str, test_tx: Transaction = tx_copy):
            logger.debug(log_state)
            logger.debug(test_tx.to_json())

        test_state("TX COPY")  # Initial copy state before modifications

        # Step 1: Remove existing script_sigs
        tx_copy = self._remove_scriptsig(tx_copy)
        test_state("REMOVE SCRIPTSIG")

        # Step 2: Insert the script_pubkey from the referenced UTXO into the input's script_sig
        ref_input = tx_copy.inputs[input_index]
        ref_utxo = self.db.get_utxo(txid=ref_input.txid, vout=ref_input.vout)

        if not ref_utxo:
            raise ValueError("Referenced UTXO not found.")

        r_txid, r_vout, r_address, r_amount, r_script_pubkey, r_spent = ref_utxo
        ref_input.script_sig = bytes(r_script_pubkey)
        ref_input.script_sig_size = write_compact_size(len(ref_input.script_sig))
        test_state("ADD SCRIPT SIG (script_pubkey as placeholder)")

        # Step 3: Get sighash tx data for hashing
        tx_sighash_data = tx.to_bytes() + sighash.to_byte()
        logger.debug("SIGHASH TX DATA")
        logger.debug(f"TYPE: {type(tx_sighash_data)}")
        logger.debug(f"{tx_sighash_data.hex()}")

        # Step 4: Hash the tx_sighash_data
        hashed_tx_data = hash256(tx_sighash_data)
        logger.debug(f"HASHED TX DATA")
        logger.debug(f"TYPE: {type(hashed_tx_data)}")
        logger.debug(f"{hashed_tx_data.hex()}")

        # Step 5: Sign the hashed_tx_data using ECDSA (uses low-s value)
        (r, s) = ecdsa(private_key, hashed_tx_data)
        logger.debug(f"ECDSA TUPLE")
        logger.debug(f"(R,S) = {(r, s)}")

        # Step 6: DER encode the signature
        serialized_signature = encode_der_signature(r, s)

        # Step 7: Append sighash byte and return for use in script sig
        serialized_signature = serialized_signature + sighash.to_byte()
        logger.debug(f"SIGNATURE: {serialized_signature.hex()}")
        return serialized_signature

    def get_segwit_sig(self, private_key: int, tx: Transaction, input_amount: int, input_index=0,
                       sighash: SigHash = SigHash.ALL) -> bytes:
        """
        Given a private key, transaction with input to be signed, and corresponding input_index, we return the
        signature for use in the scriptsig for the input.

        Legacy Signing Algorithm:
        --
            1. Construct the preimage and preimage hash

        """
        # 1. Construct the pre-image hash
        pre_image_version = tx.version  # 4 bytes | little-endian

        # Serialize and hash the txids and vouts for the inputs
        # Serialize and hash the sequences for the inputs
        serialized_inputs = b''
        serialized_sequences = b''
        for i in tx.inputs:
            serialized_inputs += i.txid + to_little_bytes(i.vout, Input.VOUT_BYTES)
            serialized_sequences += to_little_bytes(i.sequence, Input.SEQ_BYTES)
        hashed_input = hash256(serialized_inputs)
        hashed_sequences = hash256(serialized_sequences)

    def _remove_scriptsig(self, tx: Transaction) -> Transaction:
        # Remove all scriptsigs from the inputs
        for i in tx.inputs:
            i.script_sig = bytes()
            i.script_sig_size = write_compact_size(0)
        return tx


def encode_der_signature(r: int, s: int) -> bytes:
    """
    Encodes ECDSA integers r and s into a DER-encoded signature.
    """
    return encode_dss_signature(r, s)


def decode_der_signature(der_sig: bytes) -> tuple[int, int]:
    """
    Decodes a DER-encoded ECDSA signature back into integers r and s.
    """
    return decode_dss_signature(der_sig)


if __name__ == "__main__":
    # r = 41
    # s = 99
    # encode_der_signature(r, s)

    # Setup DB and start your engines
    test_db = BitCloneDatabase()
    test_db._clear_db()
    engine = TxEngine(test_db)

    # Create tx for utxo
    test_output = Output(100, bytes.fromhex('deadbeef'))
    test_tx = Transaction(outputs=[test_output])
    print(f"TEST_TX TXID: {test_tx.txid().hex()}")

    test_db.add_utxo(
        txid=test_tx.txid(),
        vout=0,
        address="dummy",
        amount=test_tx.outputs[0].amount,
        script_pubkey=test_tx.outputs[0].script_pubkey
    )

    # Create tx to sign
    test_input = Input(test_tx.txid(), 0, bytes.fromhex('babefade'), 0)
    input_tx = Transaction(inputs=[test_input])

    # Test engine
    engine.sign_legacy_tx(private_key=41, tx=input_tx)
