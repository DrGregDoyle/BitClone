"""
Testing Block and related classes
"""

from src.backup.decoder_lib import decode_block
from tests.utility import random_block


def test_block():
    block1 = random_block()
    constructed_block = decode_block(block1.encoded)
    assert constructed_block.encoded == block1.encoded
