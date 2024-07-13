"""
Classes and functions for constructing data types
"""
from src.primitive import CompactSize
from src.signature import sign_transaction, encode_signature
from src.transaction import TxInput, Transaction


def tx_engine_legacy(
        private_key: int,
        utxo_list: list,  # List of UTXOs
        output_list: list,  # List of Outputs
        sequence: int = 0,
        locktime: int = 0,
        sighash: int = 1
):
    """
    Creates a legacy raw transaction.
    """
    version = 1
    # TxInputs - no scriptsig
    input_list = []
    for utxo in utxo_list:
        pt = utxo.outpoint
        scriptsig = utxo.scriptpubkey
        temp_input = TxInput(pt.txid.hex, pt.v_out.num, scriptsig=scriptsig, sequence=sequence)
        input_list.append(temp_input)

    # Raw Tx
    raw_tx = Transaction(inputs=input_list, outputs=output_list, locktime=locktime, sighash=sighash, version=version)
    tx_hash = raw_tx.txid

    # Sign tx hash | signature algorithm uses "low s" value
    sig = sign_transaction(tx_hash, private_key)
    encoded_sig = encode_signature(sig, sighash)
    return encoded_sig.hex()


def tx_engine_segwit(
        private_key: int,
        utxo_list: list,
        output_list: list,
        sequence: int = 0,
        locktime: int = 0,
        sighash: int = 1
):
    version = 2


def remove_scriptsig_legacy(tx: Transaction):
    inputs = tx.inputs
    new_inputs = []
    for i in inputs:
        i.scriptsig = bytes(b"")
        i.scriptsig_size = CompactSize(0)
        new_inputs.append(i)
    tx.inputs = new_inputs
    return tx


# -- TESTING
from tests.utility import random_utxo, random_txoutput
from secrets import randbits

if __name__ == "__main__":
    utxo_list = [random_utxo()]
    private_key = randbits(256)
    output_list = [random_txoutput()]
    sig = tx_engine_legacy(private_key, utxo_list, output_list)
    print(f"SIG: {sig}")
