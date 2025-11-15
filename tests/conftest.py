"""
Fixtures used in the tests
"""
from random import randint
from secrets import token_bytes

import pytest

from src.core import TX
from src.script import ScriptEngine
from src.tx import TxInput, TxOutput, WitnessField, Transaction

__all__ = ["getrand_txinput", "getrand_witnessfield", "getrand_txoutput", "getrand_tx"]


# --- Generate Random Tx Elements --- #

def getrand_txinput():
    txid = token_bytes(TX.TXID)
    vout = int.from_bytes(token_bytes(TX.VOUT), "little")
    scriptsig = token_bytes(randint(40, 60))
    sequence = int.from_bytes(token_bytes(TX.SEQUENCE), "little")

    return TxInput(txid, vout, scriptsig, sequence)


def getrand_txoutput():
    amount = int.from_bytes(token_bytes(TX.AMOUNT), "little")
    scriptpubkey = token_bytes(randint(40, 60))

    return TxOutput(amount, scriptpubkey)


def getrand_witnessfield():
    item_num = randint(0, 4)
    items = [token_bytes(randint(20, 40)) for _ in range(item_num)]
    return WitnessField(items)


def getrand_tx(segwit: bool = True):
    input_num = randint(1, 4)
    output_num = randint(1, 4)
    inputs = [getrand_txinput() for _ in range(input_num)]
    outputs = [getrand_txoutput() for _ in range(output_num)]
    if segwit:
        witness = [getrand_witnessfield() for _ in range(input_num)]
    else:
        witness = None
    locktime = int.from_bytes(token_bytes(TX.LOCKTIME), "little")
    return Transaction(inputs, outputs, witness, locktime)


@pytest.fixture()
def script_engine():
    return ScriptEngine()
