"""
Testing Block and related classes
"""

from src.decoder_lib import decode_block
from tests.utility import random_block


def test_block():
    block1 = random_block()
    # print(f"BLOCK 1: {block1.to_json()}")
    # for tx in block1.tx_list:
    # print(f"TX: {tx.to_json()}")
    # print(f'TX ENCODED: {tx.encoded}')
    constructed_block = decode_block(block1.encoded)
    # print(f"BLOCK 2: {constructed_block.to_json()}")
    assert constructed_block.encoded == block1.encoded
