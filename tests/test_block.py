"""
Tests for the MerkleTree, BlockHeader and Block classes
"""

from secrets import token_bytes

from src.block import BlockHeader, Block
from src.crypto import hash256
from src.data import MerkleTree
from tests.randbtc_generators import get_random_block_header, get_random_block


def test_merkle_tree():
    """
    r1 + r2 = r_12, r3 + r3 = r_33,
    r_12 + r_33 = root
    """
    r1 = token_bytes(32)
    r2 = token_bytes(32)
    r3 = token_bytes(32)
    random_ids = [r1, r2, r3]
    random_tree = MerkleTree(random_ids)

    # Verification hashes
    r_12 = hash256(r1 + r2)
    r_33 = hash256(r3 + r3)
    root = hash256(r_12 + r_33)

    # Merkle proof lists
    r1_proof = [(r2, 'right'), (r_33, 'right')]
    r2_proof = [(r1, 'left'), (r_33, 'right')]
    r3_proof = [(r3, 'right'), (r_12, 'left')]

    # Asserts
    assert random_tree.merkle_root == root, "Merkle Root mismatch"
    assert random_tree.tree[1] == [r_12, r_33]
    assert random_tree.tree[2] == [r1, r2, r3, r3]
    assert random_tree.get_merkle_proof(r1) == r1_proof, "GetMerkle Proof mismatch"
    assert random_tree.get_merkle_proof(r2) == r2_proof, "GetMerkle Proof mismatch"
    assert random_tree.get_merkle_proof(r3) == r3_proof, "GetMerkle Proof mismatch"
    assert random_tree.verify_merkle_proof(r1_proof, r1), "VerifyMerkle Proof mismatch"
    assert random_tree.verify_merkle_proof(r2_proof, r2), "VerifyMerkle Proof mismatch"
    assert random_tree.verify_merkle_proof(r3_proof, r3), "VerifyMerkle Proof mismatch"


def test_block_header():
    rand_blockheader = get_random_block_header()
    fbrand_header = BlockHeader.from_bytes(rand_blockheader.to_bytes())
    assert rand_blockheader == fbrand_header, "Block header mismatch"


def test_block():
    rand_block = get_random_block()
    fbrand_block = Block.from_bytes(rand_block.to_bytes())

    assert rand_block == fbrand_block, "Block mismatch"
