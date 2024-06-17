"""
A file for testing leaves and merkle trees
"""
from hashlib import sha256

from src.merkle import MerkleTree, Branch, Leaf
from src.utility import get_random_string


def test_tree_methods():
    """
    We create a Merkle tree then use the Leaf class to verify the levels of the tree
    """
    hash_list = []
    random_length = 3  # Todo: Make true random length
    for x in range(random_length):
        hash_list.append(
            sha256(get_random_string().encode()).hexdigest()
        )
    test_tree = MerkleTree(elements=hash_list)

    leaf1 = Leaf(hash_list[0])
    leaf2 = Leaf(hash_list[1])
    leaf3 = Leaf(hash_list[2])

    branch12 = Branch(leaf1, leaf2)
    branch33 = Branch(leaf3, leaf3)

    branch1233 = Branch(branch12.value, branch33.value)

    assert test_tree.merkle_tree.get(0) == [branch1233.value]
    assert test_tree.merkle_tree.get(1) == [branch12.value, branch33.value]
    assert test_tree.merkle_tree.get(2) == [leaf1, leaf2, leaf3, leaf3]

    assert test_tree.verify_element(leaf1)
    assert test_tree.verify_element(leaf2)
    assert test_tree.verify_element(leaf3)
    assert test_tree.verify_element(hash_list[0])
    assert test_tree.verify_element(hash_list[1])
    assert test_tree.verify_element(hash_list[2])
    assert not test_tree.verify_element(branch12.value)
