"""
Testing the various messages
"""
from random import randint, choice
from secrets import token_bytes

from src.network import MerkleBlock, SendCompact
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


def test_send_compact():
    rand_bool = choice([0, 1])
    rand_num = int.from_bytes(token_bytes(8), "little")

    test_cpmct = SendCompact(rand_bool, rand_num)
    recovered_cpmct = SendCompact.from_bytes(test_cpmct.payload())

    assert test_cpmct.payload() == recovered_cpmct.payload(), \
        "to_bytes -> from_bytes constructino failed for SendCompact"
