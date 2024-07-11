"""
Classes and functions for constructing data types
"""
from src.predicates import CompactSize
from src.transaction import TxInput, Transaction


def tx_engine_legacy(
        outpoint_list: list,  # List of Outpoints
        output_list: list,  # List of Outputs
        sequence: int = 0,
        locktime: int = 0):
    """
    Creates a legacy raw transaction.
    """
    # TxInputs
    input_list = []
    for pt in outpoint_list:
        # Input txid will be in natural byte order, TxInput takes reverse byte order
        temp_input = TxInput(pt.txid.display, pt.v_out.num, scriptsig="", sequence=sequence)
        input_list.append(temp_input)

    # Raw Tx
    raw_tx = Transaction(inputs=input_list, outputs=output_list, locktime=locktime)
    return raw_tx


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
from tests.utility import random_tx

if __name__ == "__main__":
    tx1 = random_tx(input_num=3, output_num=1, segwit=False)
    print(tx1.to_json())
    tx2 = remove_scriptsig_legacy(tx1)

    print(tx2.to_json())
