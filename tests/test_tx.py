"""
We test the various parts of a BitClone transaction
"""
import os
import sys

from src.tx import TxIn, TxOut, Witness, Tx

sys.path.append(os.path.dirname(__file__))


def test_txinput(getrand_txinput):
    """
    We test the serialization and class method of TxInput
    """
    random_txinput = getrand_txinput()
    recovered_txinput = TxIn.from_bytes(random_txinput.to_bytes())

    assert recovered_txinput == random_txinput, "Failed to reconstruct TxInput using to_bytes -> from_bytes method"


def test_txoutput(getrand_txoutput):
    """
    We test the serialization and class method of TxOutput
    """
    random_txoutput = getrand_txoutput()
    recovered_txoutput = TxOut.from_bytes(random_txoutput.to_bytes())

    assert recovered_txoutput == random_txoutput, "Failed to reconstruct TxOutput using to_bytes -> from_bytes method"


def test_witness(getrand_witnessfield):
    """
    We test the serialization of the WitnessField class
    """
    random_witness = getrand_witnessfield()
    recovered_witness = Witness.from_bytes(random_witness.to_bytes())

    assert random_witness == recovered_witness, "Failed to reconstruct WitnessField using to_bytes -> from_bytes method"


def test_tx(getrand_tx):
    # Legacy tx first
    random_legacytx = getrand_tx(segwit=False)
    recovered_legacytx = Tx.from_bytes(random_legacytx.to_bytes())

    assert random_legacytx == recovered_legacytx, \
        "Failed to reconstruct Transaction (legacy) using to_bytes -> from_bytes method"

    # Segwit tx
    random_tx = getrand_tx()
    recovered_tx = Tx.from_bytes(random_tx.to_bytes())

    assert random_tx == recovered_tx, "Failed to reconstruct Transaction using to_bytes -> from_bytes method"
