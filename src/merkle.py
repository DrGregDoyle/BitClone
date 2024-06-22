"""
A module for Merkle trees
"""

# --- IMPORTS --- #
import json
import logging
import sys
from hashlib import sha256

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
        return self.to_json()

    def __add__(self, other):
        return self.value + other.value

    def __eq__(self, other):
        return self.value == other.value

    def to_json(self):
        return json.dumps(self.value)


class Branch:
    """
    In a Merkle Tree, we create Branches by taking the hash of the concatenation of the left and right leaves.
    We will create a Branch using a factory method to guarantee that one leaf is left and one leaf is not left
    """

    def __init__(self, left: Leaf, right: Leaf):
        self.left = left
        self.right = right
        self.value = Leaf(self.hash(self.left + self.right))

    def __repr__(self):
        return self.to_json()

    @staticmethod
    def hash(hash_string: str) -> str:
        return sha256(hash_string.encode()).hexdigest()

    def to_json(self):
        return json.dumps(self.value)


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
        # Elements of the MerkleTree are the initial list of hash values
        self.elements = elements

        # Find height of tree
        self.height = self.get_height(self.elements)

        # Create Merkle Tree
        self.merkle_tree = self.create_tree(self.elements)

        # Get Merkle Root
        self.merkle_root = self.merkle_tree.get(0)[0]

    def get_height(self, elements: list):
        height = 0
        while pow(2, height) < len(elements):
            height += 1
        return height

    def create_tree(self, elements: list):
        """
        We create the merkle tree
        """
        # Odd number of elements
        if len(elements) % 2 == 1:
            elements.append(elements[-1])

        # Create height variable
        height = self.height

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
            branch_list.append(temp_branch.value)

        return branch_list

    def find_path(self, element: str | Leaf):
        """
        We find a list of corresponding hash values necessary to verify the element is in the tree.
        """
        # Get element as Leaf
        if isinstance(element, str):
            current_leaf = Leaf(element)
        else:
            current_leaf = element

        # Verify leaf at each level and append opposite leaf
        height = self.height
        hash_dict = {}
        while height > 0:
            # Get leaves at height
            leaf_list = self.merkle_tree.get(height)

            # Verify current leaf
            if current_leaf not in leaf_list:
                logger.error(f"Did not find leaf with value {current_leaf} at height {height}")
                return None

            # Find partner leaf
            current_index = leaf_list.index(current_leaf)
            order = 1 - (current_index % 2)
            if order == 1:
                partner_leaf = leaf_list[current_index + 1]
                current_leaf = Branch(current_leaf, partner_leaf).value
            else:
                partner_leaf = leaf_list[current_index - 1]
                current_leaf = Branch(partner_leaf, current_leaf).value

            # Create partner_dict
            partner_dict = {"leaf": partner_leaf, "order": order}

            # Save partner leaf
            hash_dict.update({height: partner_dict})

            # Decrement height
            height -= 1

        return hash_dict

    def verify_element(self, element: str | Leaf):
        """
        We verify the element is in the merkle tree
        """
        # Get element path
        element_path = self.find_path(element)

        # Return False if path is None
        if element_path is None:
            return False

        # At each level, concat the current and partner leaf into new branch, which becomes current leaf
        height = self.height
        current_leaf = Leaf(element) if isinstance(element, str) else element
        while height > 0:
            # Get partner leaf and order
            partner_dict = element_path.get(height)
            partner_leaf = partner_dict["leaf"]
            partner_order = partner_dict["order"]

            # Create new branch
            (left, right) = (partner_leaf, current_leaf) if partner_order == 0 else (current_leaf, partner_leaf)
            temp_branch = Branch(left, right)

            # Update current leaf
            current_leaf = temp_branch.value

            # Decrement height
            height -= 1

        # Verify final leaf agrees with merkle root
        return current_leaf == self.merkle_root
