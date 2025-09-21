"""
We test the various parts of a BitClone transaction
"""
from random import randint
from secrets import token_bytes

from src.chain import TxInput, TxOutput, WitnessField
from src.core import TX


def test_txinput():
    """
    We test the serialization and class method of TxInput
    """
    # Generate random txInput
    txid = token_bytes(TX.TXID)
    vout = int.from_bytes(token_bytes(TX.VOUT), "big")
    scriptsig = token_bytes(32)  # Random bytes as substitute for actual script
    sequence = int.from_bytes(token_bytes(TX.SEQUENCE), "big")

    random_txinput = TxInput(txid, vout, scriptsig, sequence)
    recovered_txinput = TxInput.from_bytes(random_txinput.to_bytes())

    assert recovered_txinput == random_txinput, "Failed to reconstruct TxInput using to_bytes -> from_bytes method"


def test_txoutput():
    """
    We test the serialization and class method of TxOutput
    """
    # Generate random txOutput
    amount = int.from_bytes(token_bytes(8), "big")
    scriptpubkey = token_bytes(32)  # Random bytes as substitute for actual script

    random_txoutput = TxOutput(amount, scriptpubkey)
    recovered_txoutput = TxOutput.from_bytes(random_txoutput.to_bytes())

    assert recovered_txoutput == random_txoutput, "Failed to reconstruct TxOutput using to_bytes -> from_bytes method"


def test_witness():
    """
    We test the serialization of the WitnessField class
    """
    random_num_items = randint(3, 5)  # Between 3 and 5 witness items
    witness_items = []
    for _ in range(random_num_items):
        witness_items.append(token_bytes(randint(32, 64)))
    random_witness = WitnessField(witness_items)
    recovered_witness = WitnessField.from_bytes(random_witness.to_bytes())

    assert random_witness == recovered_witness, "Failed to reconstruct WitnessField using to_bytes -> from_bytes method"
