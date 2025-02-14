"""
Tests for the MerkleTree, BlockHeader and Block classes
"""

from secrets import token_bytes

from src.block import MerkleTree, BlockHeader
from src.library.hash_functions import hash256


def get_randint(byte_size=32):
    return int.from_bytes(token_bytes(byte_size), "big")


def get_random_header() -> BlockHeader:
    random_version = get_randint(4)
    random_id = token_bytes(32)
    random_merkleroot = token_bytes(32)
    random_timestamp = get_randint(4)
    random_bits = token_bytes(4)
    random_nonce = get_randint(4)

    return BlockHeader(random_version, random_id, random_merkleroot, random_timestamp, random_bits, random_nonce)


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
    random_header = get_random_header()
    constructed_header = BlockHeader.from_bytes(random_header.to_bytes())

    assert random_header.to_bytes() == constructed_header.to_bytes(), "From bytes mismatch"
