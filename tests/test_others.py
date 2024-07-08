"""
Tests for predicates and parser
"""
from src.parse import target_to_bits, bits_to_target
from src.predicates import CompactSize
from tests.utility import random_bits


def test_target_bits_encoding():
    _b = random_bits()
    _t = bits_to_target(_b)
    assert target_to_bits(_t) == _b


def test_compact_size():
    num1 = CompactSize(0xfc)
    num2 = CompactSize(0xfd)
    num3 = CompactSize(0xffff)
    num4 = CompactSize(0xffffffff)
    num5 = CompactSize(0xffffffffffffffff)

    assert num1.hex == "fc"
    assert num2.hex == "fdfd00"
    assert num3.hex == "fdffff"
    assert num4.hex == "feffffffff"
    assert num5.hex == "ffffffffffffffffff"
