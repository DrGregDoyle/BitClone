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
    print(f"BLOCK 1: {block1.to_json()}")
    constructed_block = decode_block(block1.encoded)
    print(f"BLOCK 2: {constructed_block.to_json()}")
    assert constructed_block.encoded == block1.encoded
