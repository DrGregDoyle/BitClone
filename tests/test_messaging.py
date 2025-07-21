"""
Testing the various messages
"""
from random import randint
from secrets import token_bytes

from src.network import MerkleBlock
from tests.randbtc_generators import get_random_block_header


def test_merkleblock():
    tx_num = randint(2, 5)
    hash_num = randint(1, 4)
    flags = token_bytes(randint(1, 2))

    random_header = get_random_block_header(tx_num)

    hashes = [token_bytes(32) for _ in range(hash_num)]
    random_merkleblock = MerkleBlock(random_header, tx_num, hashes, flags)
    print(f"RANDOM MERKLEBLOCK: {random_merkleblock.to_json()}")

    recovered_merkleblock = MerkleBlock.from_bytes(random_merkleblock.payload())
    assert random_merkleblock.payload() == recovered_merkleblock.payload(), \
        "Merkleblock failed to_bytes -> from_bytes construction"
