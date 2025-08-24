"""
Tests for the miner class
"""
from src.backup.data import target_to_bits

from src.backup.miner import Miner
from tests.backup.randbtc_generators import get_random_block


def test_miner():
    # Get random block
    rand_block = get_random_block()

    # Change bits to use low target
    low_target = bytes.fromhex("0000ff0000000000000000000000000000000000000000000000000000000000")
    rand_block.bits = target_to_bits(low_target)

    # Mine block
    miner = Miner()
    mined_block = miner.mine_block(rand_block)

    # Asserts
    assert mined_block.header.block_id_num < int.from_bytes(low_target, "big")
