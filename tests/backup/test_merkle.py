"""
A file for testing leaves and merkle trees
"""
from random import randint

from src.backup.merkle import create_merkle_tree, get_merkle_proof, verify_element
from tests.backup.utility import random_hash

UPPER = 16
LOWER = 8


def test_tree_methods():
    """
    We create a Merkle tree then use the Leaf class to verify the levels of the tree
    """
    length = randint(LOWER, UPPER)
    tx_id_list = [random_hash() for _ in range(length)]

    # Get merkle tree
    test_tree = create_merkle_tree(tx_id_list)

    # Verify each tx in tx_list
    for tx_id in tx_id_list:
        tx_proof = get_merkle_proof(tx_id, test_tree)
        assert verify_element(tx_id, tx_proof), \
            f"Did not verify element {tx_id} for merkle proof {tx_proof} for merkle tree {test_tree}"
