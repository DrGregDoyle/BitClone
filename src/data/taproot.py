"""
Helper functions and classes for P2TR
"""
import json

from src.cryptography import tapleaf_hash, tapbranch_hash
from src.data import write_compact_size

VERSION = b'\xc0'


class Leaf:
    """
    Given a taproot script, we create an object containing the script, the serialized script and the leaf hash
    """
    __slots__ = ("script", "serialized", "leaf_hash")

    def __init__(self, script: bytes, version_byte: bytes = VERSION):
        self.script = script
        self.serialized = version_byte + write_compact_size(len(script)) + self.script
        self.leaf_hash = tapleaf_hash(self.serialized)

    def to_dict(self):
        """
        Return dictionary of values for display
        """
        return {
            "script": self.script.hex(),
            "version": bytes([self.serialized[0]]).hex(),
            "size": write_compact_size(len(self.script)).hex(),
            "serialized": self.serialized.hex(),
            "leaf_hash": self.leaf_hash.hex()
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


class Branch:
    """
    Given two hash values, we perform a TapBranch hash using lexicographical ordering, along with storing left and
    right hash values
    """
    __slots__ = ("left", "right", "branch_hash")

    def __init__(self, hash1: bytes, hash2: bytes):
        self.left = hash1 if hash1 <= hash2 else hash2
        self.right = hash2 if hash1 <= hash2 else hash1
        self.branch_hash = tapbranch_hash(self.left + self.right)

    def to_dict(self):
        return {
            "left": self.left.hex(),
            "right": self.right.hex(),
            "branch_hash": self.branch_hash.hex()
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


class Tree:
    """
    The class associated with the Merkle tree of a list of leaf scripts
    """

    def __init__(self, scripts: list[bytes], tree_type: int = 0):
        """
        Default construction is a list of scripts in op-code formatting
        """
        self.leaves = [Leaf(s) for s in scripts]
        self.branches = self._get_sequential_branches(self.leaves)
        self.merkle_root = self.branches[-1].branch_hash if self.branches else self.leaves[-1].leaf_hash

    def _get_sequential_branches(self, leaves: list[Leaf]) -> list:
        if len(leaves) < 2:
            return []

        leaf1 = leaves.pop(0)
        leaf2 = leaves.pop(0)
        branches = [Branch(leaf1.leaf_hash, leaf2.leaf_hash)]
        while len(leaves) > 0:
            last_branch = branches[-1]
            next_leaf = leaves.pop(0)
            branches.append(Branch(last_branch.branch_hash, next_leaf.leaf_hash))

        return branches

    def to_dict(self):
        leaf_dict = {
            f"leaf_{x}": self.leaves[x].to_dict() for x in range(len(self.leaves))
        }
        branch_dict = {
            f"branch_{y}": self.branches[y].to_dict() for y in range(len(self.branches))
        }
        return {
            "leaves": leaf_dict,
            "branches": branch_dict,
            "merkle_root": self.merkle_root.hex()
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


def get_unbalanced_merkle_root(scripts: list[bytes], version_byte: bytes = VERSION) -> bytes:
    """
    Given a list of scripts, we perform the following:
        1) Create Leaf objects from each script
        2) Recursively create branches starting from an initial leaf pair, and then adding a subsequent leaf hash
        3) Final branch hash is the merkle root
    """
    leaves = [Leaf(s, version_byte) for s in scripts]

    # If only 1 leaf, return empty bytes object
    if len(leaves) == 1:
        return leaves[0].leaf_hash

    # For 2 or more leaves, create branches
    leaf1 = leaves.pop(0)
    leaf2 = leaves.pop(0)
    branches = [Branch(leaf1.leaf_hash, leaf2.leaf_hash)]

    # We remove a leaf from the list with each iteration
    while leaves:
        next_leaf = leaves.pop(0)
        last_branch = branches[-1]
        branches.append(Branch(next_leaf.leaf_hash, last_branch.branch_hash))

    return branches[-1].branch_hash


# --- TESTING ---
if __name__ == "__main__":
    sep = "---" * 50
    print(" --- TAPROOT --- ")
    print(sep, end="\n")

    _scripts = [
        bytes.fromhex("5187"),
        # bytes.fromhex("5287"),
        # bytes.fromhex("5387"),
        # bytes.fromhex("5487"),
        # bytes.fromhex("5587")
    ]

    test_tree = Tree(_scripts)
    print(test_tree.to_json())

    # _leaf1 = Leaf(bytes.fromhex("5187"))
    # _leaf2 = Leaf(bytes.fromhex("5287"))
    # _leaf3 = Leaf(bytes.fromhex("5387"))
    # _leaf4 = Leaf(bytes.fromhex("5487"))
    # _leaf5 = Leaf(bytes.fromhex("5587"))
    # _leaves = [_leaf1, _leaf2, _leaf3, _leaf4, _leaf5]
    #
    # _branch1 = Branch(_leaf1.leaf_hash, _leaf2.leaf_hash)
    # _branch2 = Branch(_branch1.branch_hash, _leaf3.leaf_hash)
    # _branch3 = Branch(_branch2.branch_hash, _leaf4.leaf_hash)
    # _branch4 = Branch(_branch3.branch_hash, _leaf5.leaf_hash)
    # _branches = [_branch1, _branch2, _branch3, _branch4]
    #
    # for leaf in _leaves:
    #     print(f" --- LEAF {_leaves.index(leaf) + 1} ---")
    #     print(leaf.to_json())
    #     print(sep)
    #
    # for branch in _branches:
    #     print(f" --- BRANCH {_branches.index(branch) + 1} ---")
    #     print(branch.to_json())
    #     print(sep)
    #
    # test_merkle_root = get_unbalanced_merkle_root(scripts=_scripts)
    # print(f"TEST MERKLE ROOT: {test_merkle_root.hex()}")
