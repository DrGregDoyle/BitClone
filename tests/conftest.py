"""
Fixtures used in the tests
"""
import time
from ipaddress import IPv4Address
from random import randint, choice
from secrets import token_bytes

import pytest

from src.block.block import Block
from src.core import TX, write_compact_size
from src.network import InvType
from src.network.datatypes.network_data import *
from src.network.datatypes.network_types import Services
from src.network.messages.data_msg import *
from src.script import ScriptEngine
from src.tx import TxIn, TxOut, Witness, Tx


# --- Plain helper functions (logic lives here, fixtures wrap these) --- #


def _getrand_sorted_index() -> list[int]:
    """Return a random list of sorted indices. Suitable for differentially encoded block indices"""
    index_list = [randint(0, 100) for _ in range(randint(10, 20))]
    return sorted(list(set(index_list)))


def _getrand_ipaddr() -> IPv4Address:
    rand_octets = [randint(0, 255) for _ in range(4)]
    return IPv4Address('.'.join(str(o) for o in rand_octets))


def _getrand_txinput() -> TxIn:
    return TxIn(
        txid=token_bytes(TX.TXID),
        vout=int.from_bytes(token_bytes(TX.VOUT), "little"),
        scriptsig=token_bytes(randint(40, 60)),
        sequence=int.from_bytes(token_bytes(TX.SEQUENCE), "little")
    )


def _getrand_txoutput() -> TxOut:
    return TxOut(
        amount=int.from_bytes(token_bytes(TX.AMOUNT), "little"),
        scriptpubkey=token_bytes(randint(40, 60))
    )


def _getrand_witnessfield() -> Witness:
    items = [token_bytes(randint(20, 40)) for _ in range(randint(0, 4))]
    return Witness(items)


def _getrand_tx(segwit: bool = True) -> Tx:
    input_num = randint(1, 4)
    inputs = [_getrand_txinput() for _ in range(input_num)]
    outputs = [_getrand_txoutput() for _ in range(randint(1, 4))]
    witness = [_getrand_witnessfield() for _ in range(input_num)] if segwit else None
    locktime = int.from_bytes(token_bytes(TX.LOCKTIME), "little")
    return Tx(inputs, outputs, witness, locktime)


def _getrand_coinbase(segwit: bool = True) -> Tx:
    random_height = randint(500_000, 999_999)
    random_height_bytes = random_height.to_bytes((random_height.bit_length() + 7) // 8, "big")
    coinbase_txin = TxIn(
        txid=b'\x00' * 32,
        vout=0xffffffff,
        scriptsig=write_compact_size(len(random_height_bytes)) + random_height_bytes + token_bytes(20),
        sequence=0xffffffff
    )
    witness_reserve_val = b'\x00' * 32 if segwit else None
    return Tx(
        inputs=[coinbase_txin],
        outputs=[_getrand_txoutput() for _ in range(randint(5, 10))],
        witness=[Witness(witness_reserve_val)],
        locktime=random_height + 100
    )


def _getrand_block() -> Block:
    coinbase_tx = _getrand_coinbase()
    tx_list = [_getrand_tx() for _ in range(randint(5, 10))]
    tx_list.insert(0, coinbase_tx)
    return Block(prev_block=token_bytes(32), txs=tx_list)


def _getrand_netaddr() -> NetAddr:
    return NetAddr(
        ip_addr=_getrand_ipaddr(),
        port=randint(3000, 6000),
        services=choice(list(Services)),
        timestamp=int(time.time())
    )


def _getrand_invvector(inv_type: int = None) -> InvVector:
    inv_type = inv_type if inv_type is not None else choice(list(InvType))
    return InvVector(
        inv_type=inv_type,
        obj_hash=token_bytes(32)
    )


def _getrand_prefilledtx() -> PrefilledTx:
    return PrefilledTx(
        block_index=randint(0, 100),
        tx=_getrand_tx(),
    )


def _getrand_blocktxns() -> BlockTxns:
    return BlockTxns(
        block_hash=token_bytes(32),
        txs=[_getrand_tx() for _ in range(randint(5, 10))]
    )


def _getrand_blocktxnrqst() -> BlockTxnsRequest:
    return BlockTxnsRequest(
        block_hash=token_bytes(32),
        indices=_getrand_sorted_index(),
    )


def _getrand_shortid() -> ShortID:
    return ShortID(
        block_header=token_bytes(80),
        nonce=int.from_bytes(token_bytes(randint(1, 8)), "little"),
        txid=token_bytes(32)
    )


def _getrand_headerandshortids() -> HeaderAndShortIDs:
    block = _getrand_block()
    nonce = randint(0, 999_999)
    header = block.get_header().to_bytes()

    # Coinbase is always prefilled; randomly prefill one more tx
    prefilled_indices = {0, randint(1, len(block.txs) - 1)}
    prefilled_tx_list = [PrefilledTx(i, block.txs[i]) for i in sorted(prefilled_indices)]
    shortid_list = [
        ShortID(header, nonce, block.txs[i].txid)
        for i in range(len(block.txs)) if i not in prefilled_indices
    ]
    return HeaderAndShortIDs(header, nonce, shortid_list, prefilled_tx_list)


def _getrand_blockheader():
    """Return a random BlockHeader derived from a random block."""
    return _getrand_block().get_header()


def _getrand_headers() -> Headers:
    headers = [_getrand_blockheader() for _ in range(randint(2, 6))]
    return Headers(headers)


def _getrand_inv() -> Inv:
    return Inv(
        items=[_getrand_invvector() for _ in range(randint(5, 10))]
    )


def _getrand_notfound() -> NotFound:
    return NotFound(
        items=[_getrand_invvector() for _ in range(randint(5, 10))]
    )


def _getrand_merkleblock() -> MerkleBlock:
    header = _getrand_blockheader()
    tx_num = randint(1, 500)
    hash_num = randint(1, 10)
    hashes = [token_bytes(32) for _ in range(hash_num)]
    # flags: one byte per 8 hashes, rounded up
    flag_byte_count = (hash_num * 2 + 7) // 8
    flags = token_bytes(flag_byte_count)
    return MerkleBlock(header, tx_num, hashes, flags)


def _getrand_getblocks() -> GetBlocks:
    return GetBlocks(
        version=randint(0, 0xffffffff),
        locator_hashes=[token_bytes(32) for _ in range(randint(5, 10))],
        hash_stop=bytes(32)
    )


def _getrand_getdata() -> GetData:
    return GetData(
        items=[_getrand_invvector() for _ in range(randint(5, 10))]
    )


def _getrand_getheaders() -> GetHeaders:
    return GetHeaders(
        version=randint(0, 0xffffffff),
        locator_hashes=[token_bytes(32) for _ in range(randint(5, 10))],
        hash_stop=bytes(32)
    )


# --- Factory fixtures --- #
@pytest.fixture
def getrand_getheaders():
    return _getrand_getheaders


@pytest.fixture
def getrand_headers():
    return _getrand_headers


@pytest.fixture
def getrand_inv():
    return _getrand_inv


@pytest.fixture
def getrand_notfound():
    return _getrand_notfound


@pytest.fixture
def getrand_merkleblock():
    return _getrand_merkleblock


@pytest.fixture
def getrand_getdata():
    return _getrand_getdata


@pytest.fixture
def getrand_getblocks():
    return _getrand_getblocks


@pytest.fixture
def getrand_ipaddr():
    return _getrand_ipaddr


@pytest.fixture
def getrand_invvector():
    return _getrand_invvector


@pytest.fixture
def getrand_prefilledtx():
    return _getrand_prefilledtx


@pytest.fixture
def getrand_blocktxns():
    return _getrand_blocktxns


@pytest.fixture
def getrand_blocktxnrqst():
    return _getrand_blocktxnrqst


@pytest.fixture
def getrand_headerandshortids():
    return _getrand_headerandshortids


@pytest.fixture
def getrand_shortid():
    return _getrand_shortid


@pytest.fixture
def getrand_txinput():
    return _getrand_txinput


@pytest.fixture
def getrand_txoutput():
    return _getrand_txoutput


@pytest.fixture
def getrand_witnessfield():
    return _getrand_witnessfield


@pytest.fixture
def getrand_tx():
    return _getrand_tx


@pytest.fixture
def getrand_coinbase():
    return _getrand_coinbase


@pytest.fixture
def getrand_block():
    return _getrand_block


@pytest.fixture
def getrand_netaddr():
    return _getrand_netaddr


# --- ENGINE FIXTURES --- #

@pytest.fixture()
def script_engine():
    return ScriptEngine()
