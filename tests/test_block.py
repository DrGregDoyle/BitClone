"""
Testing Block and related classes
"""

from random import randint

from src.cipher import decode_header, decode_block
from src.miner import Miner
from tests.utility import random_header, random_block


def test_header():
    tx_num = randint(5, 10)
    _h = random_header(tx_num)
    h1 = decode_header(_h.bytes)
    h2 = decode_header(_h.hex)

    assert h1.bytes == _h.bytes
    assert h2.bytes == _h.bytes


def test_block():
    _b = random_block()
    b1 = decode_block(_b.bytes)
    b2 = decode_block(_b.hex)

    assert b1.bytes == _b.bytes
    assert b2.bytes == _b.bytes


def test_mining():
    fixed_bits = "2000ffff"
    fixed_target_int = int("00ffff0000000000000000000000000000000000000000000000000000000000", 16)

    _b = random_block(nonce=0)
    _b.header.bits = fixed_bits
    m = Miner()
    mined_block = m.mine_block(_b)

    assert int(mined_block.header.id, 16) <= fixed_target_int
