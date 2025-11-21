"""
Helper functions and classes for P2TR
"""
import json

from src.core import TaprootError, TAPROOT
from src.cryptography import tapleaf_hash, tapbranch_hash, taptweak_hash, Point
from src.data.compact_size import write_compact_size
from src.data.ecc_keys import PubKey

VERSION_BYTE = TAPROOT.VERSION_BYTE
PUBKEY_BYTELEN = TAPROOT.PUBKEY_BYTELEN

__all__ = ["Leaf", "Branch", "Tree", "TweakPubkey", "get_unbalanced_merkle_root", "get_control_byte",
           "get_control_block", "get_tweak"]


class Leaf:
    """
    Given a taproot script, we create an object containing the script, the serialized script and the leaf hash
    """
    __slots__ = ("script", "serialized", "leaf_hash")

    def __init__(self, script: bytes):
        self.script = script
        self.serialized = VERSION_BYTE + write_compact_size(len(script)) + self.script
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
        # Copy list
        leaves_copy = leaves.copy()

        if len(leaves_copy) < 2:
            return []

        leaf1 = leaves_copy.pop(0)
        leaf2 = leaves_copy.pop(0)
        branches = [Branch(leaf1.leaf_hash, leaf2.leaf_hash)]
        while len(leaves_copy) > 0:
            last_branch = branches[-1]
            next_leaf = leaves_copy.pop(0)
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


class TweakPubkey:
    """
    Given an x-only pubkey, we calculate the tweak and tweaked pubkey
    """

    def __init__(self, xonly_pubkey: bytes, merkle_root: bytes = b''):
        # --- Validation --- #
        try:
            self.internal_pubkey = PubKey.from_xonly(xonly_pubkey)
        except TaprootError as e:
            raise f"Invalid x-only pubkey: {e}"

        self.merkle_root = merkle_root
        self.tweak = taptweak_hash(xonly_pubkey + merkle_root)
        self.tweaked_pubkey = self.internal_pubkey.tweak_pubkey(self.tweak)

    def to_dict(self):
        return {
            "internal_pubkey": self.internal_pubkey.to_dict(),
            "merkle_root": self.merkle_root.hex(),
            "tweak": self.tweak.hex(),
            "tweaked_pubkey": self.tweaked_pubkey.to_dict()
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


def get_unbalanced_merkle_root(scripts: list[bytes]) -> bytes:
    """
    Given a list of scripts, we perform the following:
        1) Create Leaf objects from each script
        2) Recursively create branches starting from an initial leaf pair, and then adding a subsequent leaf hash
        3) Final branch hash is the merkle root
    """
    leaves = [Leaf(s) for s in scripts]

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


def get_control_byte(pubkey_point: Point) -> bytes:
    parity_bit = pubkey_point.y % 2
    return bytes([int.from_bytes(VERSION_BYTE, "big") + parity_bit])


def get_control_block(xonly_pubkey_bytes: bytes, merkle_root: bytes, merkle_path: bytes = b'') -> bytes:
    # Get tweaked_pubkey
    tweaked_pubkey = TweakPubkey(xonly_pubkey=xonly_pubkey_bytes, merkle_root=merkle_root)
    # Get control byte
    control_byte = get_control_byte(tweaked_pubkey.tweaked_pubkey.to_point())
    # control block = control_byte + internal xonly pubkey + merkle_path
    return control_byte + xonly_pubkey_bytes + merkle_path


def get_tweak(xonly_pubkey: bytes, merkle_root: bytes) -> bytes:
    # TODO: Add common validation methods for common datatypes, e.g, xonly_pubkey, etc..
    return taptweak_hash(xonly_pubkey + merkle_root)


# --- TESTING ---
if __name__ == "__main__":
    sep = "---" * 50

    xonly_pubkey = bytes.fromhex("924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329")
    pubkey_point = PubKey.from_bytes(xonly_pubkey)
    leaf_scripts = [
        bytes.fromhex("5187"),
        bytes.fromhex("5287"),
        bytes.fromhex("5387"),
        bytes.fromhex("5487"),
        bytes.fromhex("5587")
    ]
    leaves = [Leaf(s) for s in leaf_scripts]
    tree = Tree(leaf_scripts)

    # --- LOGGING
    print(f'TREE: {tree.to_json()}')
