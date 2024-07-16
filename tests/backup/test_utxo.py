"""
A file for testing the UTXO class and similar methods
"""

from src.backup.cipher import decode_outpoint, decode_utxo
from tests.utility import random_outpoint, random_utxo


def test_outpoint():
    _t = random_outpoint()
    t1 = decode_outpoint(_t.bytes)
    t2 = decode_outpoint(_t.hex)

    assert t1.bytes == _t.bytes
    assert t2.bytes == _t.bytes


def test_utxo():
    _u = random_utxo()
    u1 = decode_utxo(_u.bytes)
    u2 = decode_utxo(_u.hex)

    assert u1.bytes == _u.bytes
    assert u2.bytes == _u.bytes
