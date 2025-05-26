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

    def _build_balanced_tree(self, leaves: list[bytes]):
        """
        Build balanced tree - standard Merkle Tree construction
        """
        if len(leaves) == 1:
            return leaves[0]

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
        return level[0]  # root

    def _build_unbalanced_tree(self, leaves: list[bytes]):
        """
        Build unbalanced tree - first two leaves make up branch 1, then every subsequent leaf + previous branch makes
        the next branch. The final branch is the merkle root

        """
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

    def get_merkle_path(self, leaf_script: bytes) -> list[bytes]:
        """
        Given a leaf script, return the merkle path (list of sibling hashes) needed to reconstruct the root.
        Returns empty list if leaf_script is not found in the tree.
        """
        # Find the target leaf
        target_leaf = None
        target_index = None
        for i, leaf in enumerate(self.leaves):
            if leaf.leaf_script == leaf_script:
                target_leaf = leaf
                target_index = i
                break

        if target_leaf is None:
            return []  # Leaf not found

        if len(self.leaves) == 1:
            return []  # Single leaf tree has empty path

        if self.balanced:
            return self._get_balanced_merkle_path(target_index)
        else:
            return self._get_unbalanced_merkle_path(target_index)

    def _get_balanced_merkle_path(self, target_index: int) -> list[bytes]:
        """Get merkle path for balanced tree construction"""
        path = []
        current_index = target_index
        level_size = len(self.leaves)

        # Work our way up the tree level by level
        while level_size > 1:
            # Find sibling index
            if current_index % 2 == 0:
                # Left node, sibling is to the right
                sibling_index = current_index + 1
                if sibling_index >= level_size:
                    # Odd number of nodes, sibling is itself (duplicated)
                    sibling_index = current_index
            else:
                # Right node, sibling is to the left
                sibling_index = current_index - 1

            # Find the sibling hash at this level
            if level_size == len(self.leaves):
                # First level - use leaf hashes
                sibling_hash = self.leaves[sibling_index].leaf_hash
            else:
                # Higher levels - find corresponding branch hash
                # This is complex for balanced trees, so we'll use a simpler approach
                # by reconstructing the path from the stored branches
                pass

            path.append(sibling_hash)
            current_index //= 2
            level_size = (level_size + 1) // 2

        # For simplicity in balanced trees, we'll use branch traversal
        return self._traverse_for_path(target_index)

    def _traverse_for_path(self, target_index: int) -> list[bytes]:
        """Traverse stored branches to find path - works for both balanced and unbalanced"""
        path = []
        target_hash = self.leaves[target_index].leaf_hash

        # For each branch, check if our target is involved
        for branch in self.branches:
            # Check if target_hash is one of the inputs to this branch
            if self._hash_in_branch_ancestry(target_hash, branch):
                # Find the sibling hash
                if branch.left != target_hash:
                    path.append(branch.left)
                    target_hash = branch.branch_hash
                elif branch.right != target_hash:
                    path.append(branch.right)
                    target_hash = branch.branch_hash

        return path

    def _get_unbalanced_merkle_path(self, target_index: int) -> list[bytes]:
        """Get merkle path for unbalanced tree construction"""
        path = []

        if target_index == 0:
            # First leaf - path includes second leaf, then all subsequent branch hashes
            if len(self.leaves) > 1:
                path.append(self.leaves[1].leaf_hash)
                # Add remaining branches that don't include our target
                for i in range(1, len(self.branches)):
                    path.append(self.leaves[i + 1].leaf_hash)
        else:
            # Other leaves - path includes the branch hash from previous combinations
            # This is simpler to compute by traversing the stored branches
            return self._traverse_for_path(target_index)

        return path

    def _hash_in_branch_ancestry(self, target_hash: bytes, branch: Branch) -> bool:
        """Check if a hash is used in constructing this branch"""
        return target_hash == branch.left or target_hash == branch.right

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


# --- TESTING
if __name__ == "__main__":
    leaf1_script = bytes.fromhex("5187")
    leaf2_script = bytes.fromhex("5287")
    leaf3_script = bytes.fromhex("5387")
    leaf4_script = bytes.fromhex("5487")
    leaf5_script = bytes.fromhex("5587")
    test_tree = ScriptTree([leaf1_script, leaf2_script, leaf3_script, leaf4_script, leaf5_script], balanced=False)
    print(f"TEST MERKLE ROOT: {test_tree.root.hex()}")
    print(f"TEST TREE BRANCHES: {[b.branch_hash.hex() for b in test_tree.branches]}")
