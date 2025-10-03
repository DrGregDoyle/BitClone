"""
Tests for the MerkleTree class
"""
import random
from secrets import token_bytes

from src.data import MerkleTree


def test_merkle_proof():
    """
    We construct a random MerkleTree and verify the merkleproof for each id
    """
    id_num = random.randint(5, 10)
    id_list = [token_bytes(32) for _ in range(id_num)]

    random_tree = MerkleTree(id_list)

    for x in range(len(id_list)):
        temp_id = id_list[0]
        temp_merkle_proof = random_tree.get_merkle_proof(temp_id)
        assert random_tree.verify_merkle_proof(temp_merkle_proof,
                                               temp_id), "Failed Merkle proof validation for random id"
