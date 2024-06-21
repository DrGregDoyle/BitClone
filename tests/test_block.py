"""
Testing Block and related classes
"""

from src.decoder_lib import decode_block, decode_header
from tests.utility import random_header, random_block


def test_header():
    header1 = random_header()
    constructed_header = decode_header(header1.encoded)
    assert constructed_header.encoded == header1.encoded


def test_block():
    block1 = random_block()
    constructed_block = decode_block(block1.encoded)
    assert constructed_block.encoded == block1.encoded
