"""
Testing Block and related classes
"""

from random import randint

from src.cipher import decode_header, decode_block
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
