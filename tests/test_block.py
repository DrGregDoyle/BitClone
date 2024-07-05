"""
Testing Block and related classes
"""

from random import randint

from src.cipher import decode_header
from tests.utility import random_header


def test_header():
    tx_num = randint(5, 10)
    _h = random_header(tx_num)
    h1 = decode_header(_h.bytes)
    h2 = decode_header(_h.hex)

    assert h1.bytes == _h.bytes
    assert h2.bytes == _h.bytes
