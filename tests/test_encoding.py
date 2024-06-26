"""
Tests for encoding and decoding
"""
from src.encoder_lib import target_to_bits, bits_to_target
from tests.utility import get_random_bits


def test_bits_target_encoding():
    test_bits = get_random_bits()
    assert target_to_bits(bits_to_target(test_bits)) == test_bits
