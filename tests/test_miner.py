"""
Tests for the miner class
"""
from src.miner import Miner
from tests.randbtc_generators import get_random_block


def test_miner():
    rand_block = get_random_block()
    rand_block.bits = bytes.fromhex("1f00ff00")

    low_target = bytes.fromhex("0000ff0000000000000000000000000000000000000000000000000000000000")

    miner = Miner()
    mined_block = miner.mine_block(rand_block)

    # Asserts
    assert mined_block.header.block_id_num < int.from_bytes(low_target, "big")
