"""
Fixtures used in the tests
"""
import time
from ipaddress import IPv4Address
from random import randint, choice, sample
from secrets import token_bytes

import pytest

from src.block.block import Block
from src.core import TX, write_compact_size
from src.network.datatypes.network_data import NetAddr, BlockTransactions, PrefilledTx
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


# Plain function - can be called directly
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


# Fixture wraps the plain function for tests that need it injected
@pytest.fixture
def getrand_tx_fixture():
    return getrand_tx


def getrand_coinbase(segwit: bool = True):
    """Get random coinbase tx"""
    # --- Coinbase TxIn
    random_height = randint(500_000, 999_999)
    random_height_bytes = random_height.to_bytes((random_height.bit_length() + 7) // 8, "big")
    coinbase_txin = TxIn(
        txid=b'\x00' * 32,
        vout=0xffffffff,
        scriptsig=write_compact_size(len(random_height_bytes)) + random_height_bytes + token_bytes(20),
        sequence=0xffffffff
    )
    output_list = [getrand_txoutput() for _ in range(randint(5, 10))]
    witness_reserve_val = b'\x00' * 32 if segwit else None

    return Transaction(
        inputs=[coinbase_txin],
        outputs=output_list,
        witness=[Witness(witness_reserve_val)],
        locktime=random_height + 100
    )


def make_outpoint(txid: bytes, vout: int):
    return txid + vout.to_bytes(TX.VOUT, "little")


@pytest.fixture
def getrand_block():
    """Returns a random block"""
    # TODO: Add factory to use is_segwit bool
    coinbase_tx = getrand_coinbase()
    tx_list = [getrand_tx() for _ in range(randint(5, 10))]
    tx_list.insert(0, coinbase_tx)
    prev_block = token_bytes(32)
    return Block(
        prev_block=prev_block,
        txs=tx_list,
    )


@pytest.fixture
def getrand_blocktxns():
    """We return a random BlockTransaction"""
    random_hash = token_bytes(32)
    txs = [getrand_tx() for _ in range(randint(5, 10))]
    return BlockTransactions(random_hash, txs)


def getrand_headerandshortids():
    """We return a random HeaderAndShortIds"""
    # --- Get block
    random_block = getrand_block()

    # --- Fill out prefilled txs
    tx_list = random_block.txs.copy()
    tx_list.pop(0)  # Remove coinbase
    indices_to_remove = set(sample(range(1, len(tx_list) + 1), randint(1, 3)))
    indexed_txs = list(enumerate(tx_list, start=1))  # Gives a list of tuples: (block_index, tx) for prefilled txs
    indexed_txs = [(i, tx) for i, tx in indexed_txs if i not in indices_to_remove]  # Remove based on block index
    prefilled_txs = [PrefilledTx(block_index, tx) for block_index, tx in indexed_txs]

    # --- Fill out shortIds

    # --- Fill out header and shortids


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
    def _factory():
        rand_ip = getrand_ipaddr()
        rand_port = randint(3000, 6000)
        rand_service = choice(list(Services))
        rand_time = int(time.time())
        return NetAddr(rand_ip, rand_port, rand_service, timestamp=rand_time)

    return _factory


@pytest.fixture()
def script_engine():
    return ScriptEngine()


@pytest.fixture()
def sig_engine():
    return SignatureEngine()
