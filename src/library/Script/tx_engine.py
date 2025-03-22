"""
The TxEngine class - Used for signing a transaction
"""

from src.db import BitCloneDatabase
from src.library.data_handling import write_compact_size
from src.library.ecdsa import ecdsa
from src.library.hash_functions import hash256
from src.logger import get_logger
from src.tx import Transaction, Output, Input

logger = get_logger(__name__)

from enum import IntEnum

from src.library.Script.stack import BTCNum


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

    def sign_legacy_tx(self, private_key: int, tx: Transaction, input_index=0, sighash: SigHash = SigHash.ALL) -> bytes:
        """
        Signs a legacy Bitcoin transaction input and returns the transaction data to be signed.

        Legacy Signing Algorithm:
        --
            1. Remove all existing script_sigs
            2. Put the script_pubkey from referenced output in the script_sig for the input.
            3. Append the sighash byte(s) at the end of the serialized tx data
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

        # Step 5: Sign the hashed_tx_data using ECDSA
        ecdsa_sig = ecdsa(private_key, hashed_tx_data)

    def _remove_scriptsig(self, tx: Transaction) -> Transaction:
        # Remove all scriptsigs from the inputs
        for i in tx.inputs:
            i.script_sig = bytes()
            i.script_sig_size = write_compact_size(0)
        return tx


if __name__ == "__main__":
    # Setup DB and start your engines
    test_db = BitCloneDatabase(
        db_path="C:\\GREG\\Programming\\BitClone\\src\\bitclone_db\\bitclone.db"
    )
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
