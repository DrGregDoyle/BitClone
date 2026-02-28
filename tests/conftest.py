"""
Fixtures used in the tests
"""
import time
from ipaddress import IPv4Address
from random import randint, choice
from secrets import token_bytes

import pytest

from src.core import TX
from src.network.datatypes.network_data import NetAddr
from src.network.datatypes.network_types import Services
from src.script import ScriptEngine, SignatureEngine
from src.tx import TxIn, TxOut, Witness, Transaction

__all__ = ["getrand_txinput", "getrand_witnessfield", "getrand_txoutput", "getrand_tx", "make_outpoint",
           "getrand_netaddr"]


# --- Generate Random Tx Elements --- #

def getrand_txinput():
    txid = token_bytes(TX.TXID)
    vout = int.from_bytes(token_bytes(TX.VOUT), "little")
    scriptsig = token_bytes(randint(40, 60))
    sequence = int.from_bytes(token_bytes(TX.SEQUENCE), "little")

    return TxIn(txid, vout, scriptsig, sequence)


def getrand_txoutput():
    amount = int.from_bytes(token_bytes(TX.AMOUNT), "little")
    scriptpubkey = token_bytes(randint(40, 60))

    return TxOut(amount, scriptpubkey)


def getrand_witnessfield():
    item_num = randint(0, 4)
    items = [token_bytes(randint(20, 40)) for _ in range(item_num)]
    return Witness(items)


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


def make_outpoint(txid: bytes, vout: int):
    return txid + vout.to_bytes(TX.VOUT, "little")


# --- Generate Random Network Data Elements --- #
def getrand_ipaddr() -> IPv4Address:
    """
    We generate a random IPV4 address
    """
    rand_octets = [randint(0, 255) for _ in range(4)]
    ipaddr = '.'.join(str(octet) for octet in rand_octets)
    return IPv4Address(ipaddr)


@pytest.fixture
def getrand_netaddr():
    def _factory(is_version=True):
        rand_ip = getrand_ipaddr()
        rand_port = randint(3000, 6000)
        rand_service = choice(list(Services))
        rand_time = None if is_version else int(time.time())
        return NetAddr(rand_ip, rand_port, rand_service, timestamp=rand_time, is_version=is_version)

    return _factory


@pytest.fixture()
def script_engine():
    return ScriptEngine()


@pytest.fixture()
def sig_engine():
    return SignatureEngine()


if __name__ == "__main__":
    getrand_ipaddr()
