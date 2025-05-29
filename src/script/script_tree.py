"""
A class for Taproot merkle trees
"""
from __future__ import annotations

from src.crypto import tagged_hash_function, HashType
from src.data import write_compact_size

# --- TAPROOT CONSTANTS
VERSION_BYTE = b'\xc0'
LEAF_TAG = b'TapLeaf'
BRANCH_TAG = b'TapBranch'
TWEAK_TAG = b'TapTweak'
HASH_TYPE = HashType.SHA256
HASH_SIZE = 32


class Leaf:
    """
    Constructed with the corresponding script for the leaf
    """

    def __init__(self, leaf_script: bytes):
        self.leaf_script = leaf_script
        self.leaf_hash = tagged_hash_function(self._encode_data(leaf_script), LEAF_TAG, HASH_TYPE)

    def _encode_data(self, leaf_script: bytes):
        return VERSION_BYTE + write_compact_size(len(leaf_script)) + leaf_script


class Branch:
    """
    Given a pair of Branch or Leaf objects, we sort them lexicographically and store the branch hash
    """
    branch_hash = None

    def __init__(self, hash_1: bytes | Leaf | "Branch", hash_2: bytes | Leaf | "Branch"):
        # Extract the actual hash from each input
        if isinstance(hash_1, Leaf):
            _hash1 = hash_1.leaf_hash
        elif isinstance(hash_1, Branch):
            _hash1 = hash_1.branch_hash
        else:
            _hash1 = hash_1

        if isinstance(hash_2, Leaf):
            _hash2 = hash_2.leaf_hash
        elif isinstance(hash_2, Branch):
            _hash2 = hash_2.branch_hash
        else:
            _hash2 = hash_2

        self.left = min(_hash1, _hash2)
        self.right = max(_hash1, _hash2)
        self.branch_hash = tagged_hash_function(self.left + self.right, BRANCH_TAG, HASH_TYPE)


class ScriptTree:
    """
    Given a list of scripts, create the canonical Taproot Merkle tree using Leaf and Branch objects.
    """

    def __init__(self, scripts: list[bytes], balanced=True):
        self.balanced = balanced
        self.scripts = scripts
        self.leaves = [Leaf(s) for s in self.scripts]
        self.branches = []
        self.root = self._build_tree(self.leaves)

    def _build_tree(self, hash_list: list):
        # Get copy of leaves
        leaves = hash_list.copy()

        # Build tree based on balanced flag
        if self.balanced:
            return self._build_balanced_tree(leaves)
        else:
            return self._build_unbalanced_tree(leaves)

    def _build_balanced_tree(self, leaves: list[Leaf]):
        """
        Build balanced tree - standard Merkle Tree construction
        """
        if len(leaves) == 1:
            return leaves[0].leaf_hash

        level = leaves[:]
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                if i + 1 < len(level):
                    right = level[i + 1]
                else:
                    # If odd number of nodes, duplicate the last (Taproot/Bitcoin convention)
                    right = left
                branch = Branch(left, right)
                self.branches.append(branch)
                next_level.append(branch)
            level = next_level
        return level[0].branch_hash  # root

    def _build_unbalanced_tree(self, leaves: list[bytes]):
        """
        Build unbalanced tree - first two leaves make up branch 1, then every subsequent leaf + previous branch makes
        the next branch. The final branch is the merkle root

        """
        # Check for single leaf
        if len(leaves) == 1:
            return leaves[0].leaf_hash

        # Repeat until list is empty
        current_branch = None
        while len(leaves) > 0:
            if not self.branches:
                hash1, hash2 = leaves.pop(0), leaves.pop(0)
                current_branch = Branch(hash1, hash2)
            else:
                leaf_hash = leaves.pop(0)
                current_branch = Branch(leaf_hash, current_branch)
            self.branches.append(current_branch)
        return current_branch.branch_hash

    def get_merkle_path(self, leaf_script: bytes):
        """
        We return the concatenation of the merkle path which yields the merkle root of the class
        """
        # Check script
        if leaf_script not in self.scripts:
            raise ValueError(f"Given leaf script not in scripts list: {leaf_script}")

        # Create leaf
        leaf = Leaf(leaf_script)

        # Handled based on balanced
        if self.balanced:
            return self._get_balanced_merkle_path(leaf)
        else:
            return self._get_unbalanced_merkle_path(leaf.leaf_hash)

    def _get_balanced_merkle_path(self, leaf: Leaf):
        pass

    def _get_unbalanced_merkle_path(self, leaf: Leaf):
        # Find the leaf hash index
        hash_index = self.leaves.index(leaf)

    @staticmethod
    def eval_merkle_path(leaf_script: bytes, merkle_path: bytes) -> bytes:
        """
        Given a leaf_script and merkle path, we create the leaf_hash and calculate the merkle root based on the
        merkle path
        """
        # Verify merkle_path size
        if len(merkle_path) % HASH_SIZE != 0:
            raise ValueError(f"Merkle path must be divisible by {HASH_SIZE}")

        # Break merkle_path into 32-byte chunks
        sibling_hashes = [merkle_path[i:i + HASH_SIZE] for i in range(0, len(merkle_path), HASH_SIZE)]

        # Get leaf hash
        target_leaf = Leaf(leaf_script)
        current_hash = target_leaf.leaf_hash

        # Build merkle root
        for sibling_hash in sibling_hashes:
            temp_branch = Branch(current_hash, sibling_hash)
            current_hash = temp_branch.branch_hash

        return current_hash
