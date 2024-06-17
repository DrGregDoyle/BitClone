"""
A module for Merkle trees
"""

# --- IMPORTS --- #
import logging
import sys
from hashlib import sha256

from src.utility import get_random_string

# --- LOGGING --- #
log_level = logging.DEBUG
logger = logging.getLogger(__name__)
logger.setLevel(log_level)
logger.addHandler(logging.StreamHandler(stream=sys.stdout))


# --- CLASSES --- #
class Leaf:
    """
    In a Merkle Tree, those elements composing the initial data elements of the tree.
    """

    def __init__(self, data: str):
        self.value = data

    def __repr__(self):
        return self.value

    def __add__(self, other):
        return self.value + other.value

    def __eq__(self, other):
        return self.value == other.value


class Branch:
    """
    In a Merkle Tree, we create Branches by taking the hash of the concatenation of the left and right leaves
    """

    def __init__(self, left: Leaf, right: Leaf):
        self.left = left
        self.right = right
        self.value = self.hash(self.left + self.right)

    def __repr__(self):
        return self.value

    @staticmethod
    def hash(hash_string: str) -> str:
        return sha256(hash_string.encode()).hexdigest()

    def to_leaf(self):
        return Leaf(self.value)


class MerkleTree:
    """
    We create a Merkle Tree from an initial list of elements. The tree is given in dictionary form, where each level
    of the tree has the associated hash of the leaves in the next level.

    We will use a Tree Factory for creating trees.
    """

    def __init__(self, elements: list):
        """
        Using a Tree Factory, we are guaranteed to be given a non-empty list of string elements.
        """
        self.elements = elements
        self.merkle_tree = self.create_tree(self.elements)

    def create_tree(self, elements: list):
        """
        We create the merkle tree
        """
        # Odd number of elements
        if len(elements) % 2 == 1:
            elements.append(elements[-1])

        # Calculate height
        height = 0
        while pow(2, height) < len(elements):
            height += 1

        # Create initial list of leaves
        leaf_list = [Leaf(e) for e in elements]

        # Create lowest level of merkle tree
        merkle_tree = {height: leaf_list}

        # Create remaining levels of merkle tree
        while height > 0:
            height -= 1
            leaf_list = self.create_branches(leaf_list)
            merkle_tree.update({height: leaf_list})

        # Return merkle tree dict
        return merkle_tree

    def create_branches(self, leaf_list: list):
        """
        Given a list of leaves, we create the associated branches and return as a list of branch.to_leaf
        """
        branch_list = []
        cardinality = len(leaf_list)

        # Odd number of leaves
        if cardinality % 2 == 1:
            leaf_list.append(leaf_list[-1])

        # Create branches
        for x in range(cardinality // 2):
            temp_branch = Branch(
                left=leaf_list[2 * x],
                right=leaf_list[2 * x + 1]
            )
            branch_list.append(temp_branch.to_leaf())

        return branch_list


# --- TESTING --- #
if __name__ == "__main__":
    hash1 = sha256(get_random_string().encode()).hexdigest()
    hash2 = sha256(get_random_string().encode()).hexdigest()
    hash3 = sha256(get_random_string().encode()).hexdigest()
    elements = [hash1, hash2, hash3]

    hash12 = sha256((hash1 + hash2).encode()).hexdigest()
    hash33 = sha256((hash3 + hash3).encode()).hexdigest()
    hash1233 = sha256((hash12 + hash33).encode()).hexdigest()

    test_tree = MerkleTree(elements)
    for k in test_tree.merkle_tree.keys():
        print(f"LEVEL: {k}")
        print(f"ELEMENTS: {test_tree.merkle_tree.get(k)}")
        print("=====")
        element_list = test_tree.merkle_tree.get(k)
        for e in element_list:
            print(f"ELEMENT: {e}")
            print(f"TYPE: {type(e)}")
            print("-----")
        print("=====")

    print(f"HASH123: {hash1233}")
    print(f"HASH12: {hash12}")
    print(f"HASH33: {hash33}")
