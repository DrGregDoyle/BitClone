"""
Tests for predicates and parser
"""
from src.parse import target_to_bits, bits_to_target
from tests.utility import random_bits


def test_target_bits_encoding():
    _b = random_bits()
    _t = bits_to_target(_b)
    assert target_to_bits(_t) == _b
