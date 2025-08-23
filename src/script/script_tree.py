"""
A class for Taproot merkle trees
"""
from __future__ import annotations

from src.data.formats import Taproot
from src.script.script_utils import tapleaf_hash, tapbranch_hash

__all__ = ["Leaf", "Branch", "ScriptTree"]

_tap = Taproot


class Leaf:
    """
    Constructed with the corresponding script for the leaf
    """

    def __init__(self, leaf_script: bytes):
        self.leaf_script = leaf_script
        self.leaf_hash = tapleaf_hash(leaf_script)


class Branch:
    """Lexicographically ordered branch of two 32-byte hashes (Leaf/Branch/bytes)."""
    __slots__ = ("branch_hash",)

    def __init__(self, a: bytes | Leaf | "Branch", b: bytes | Leaf | "Branch"):
        # Extract 32-byte hashes
        h1 = a.leaf_hash if isinstance(a, Leaf) else (a.branch_hash if isinstance(a, Branch) else a)
        h2 = b.leaf_hash if isinstance(b, Leaf) else (b.branch_hash if isinstance(b, Branch) else b)

        h1 = bytes(h1)
        h2 = bytes(h2)
        if len(h1) != 32 or len(h2) != 32:
            raise ValueError("Branch children must be 32-byte hashes")

        # Lexicographic order (single comparison)
        left, right = (h1, h2) if h1 <= h2 else (h2, h1)

        # BIP341 TapBranch(tagged_hash) over concatenation
        self.branch_hash = tapbranch_hash(left + right)


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

        # Error checking
        if not leaves:
            raise ValueError("Cannot build Merkle tree from empty leaves")

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

    def _build_unbalanced_tree(self, leaves: list[Leaf]):
        """
        Build unbalanced tree - first two leaves make up branch 1, then every subsequent leaf + previous branch makes
        the next branch. The final branch is the merkle root
        """
        # Store length
        n = len(leaves)

        # Check for single leaf
        if n == 1:
            return leaves[0].leaf_hash

        # Initial branch: leaves[0] and leaves[1]
        current = Branch(leaves[0], leaves[1])
        self.branches.append(current)

        # Fold remaining leaves into the current branch
        for i in range(2, n):
            current = Branch(leaves[i], current)  # preserve original left=leaf, right=prev-branch order
            self.branches.append(current)

        return current.branch_hash

    def get_merkle_path(self, leaf_script: bytes):
        """
        We return the concatenation of the merkle path which yields the merkle root of the class
        """
        # Check script
        if leaf_script not in self.scripts:
            raise ValueError(f"Given leaf script not in scripts list: {leaf_script}")

        # Get leaf hash
        leaf_hash = Leaf(leaf_script).leaf_hash

        # Handled based on balanced
        if self.balanced:
            return self._get_balanced_merkle_path(leaf_hash)
        else:
            return self._get_unbalanced_merkle_path(leaf_hash)

    def _get_balanced_merkle_path(self, leaf_hash: bytes):
        target_hash = leaf_hash
        merkle_path = b''

        # Start with the leaves level
        current_level = [leaf_obj.leaf_hash for leaf_obj in self.leaves]

        while len(current_level) > 1:
            # Find target hash in current level
            if target_hash not in current_level:
                raise ValueError("Target hash not found in current level")

            index = current_level.index(target_hash)

            # Find sibling
            sibling_index = index + 1 if index % 2 == 0 else index - 1

            # Handle odd number of nodes (duplicate last node)
            if sibling_index >= len(current_level):
                sibling_hash = current_level[index]  # Duplicate self
            else:
                sibling_hash = current_level[sibling_index]

            # Add sibling to merkle path
            merkle_path += sibling_hash

            # Build next level
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]

                # Create branch with lexicographic sorting (as Branch class does)
                branch = Branch(left, right)
                next_level.append(branch.branch_hash)

            # Update target_hash for next iteration
            target_hash = Branch(target_hash, sibling_hash).branch_hash
            current_level = next_level

        return merkle_path

    def _get_unbalanced_merkle_path(self, leaf_hash: bytes):
        # Find the leaf hash index using next() with enumerate
        try:
            hash_index = next(i for i, leaf_obj in enumerate(self.leaves) if leaf_obj.leaf_hash == leaf_hash)
        except StopIteration:
            raise ValueError("Leaf hash not found")

        # Create merkle_path
        if hash_index <= 1:
            # Get the other leaf from the first pair
            other_index = 1 - hash_index  # Will be 0 if hash_index is 1 and vice versa
            initial_hash = self.leaves[other_index].leaf_hash
            merkle_path = initial_hash + b''.join(b.branch_hash for b in self.branches)
        else:
            # Combine branch and leaf hashes in one comprehension
            branch_hashes = (self.branches[x].branch_hash for x in range(hash_index - 1))
            leaf_hashes = (self.leaves[y].leaf_hash for y in range(hash_index + 1, len(self.leaves)))
            merkle_path = b''.join(branch_hashes) + b''.join(leaf_hashes)

        # Verify (optional - you might want to remove this in production for performance)
        if self.eval_merkle_path(self.leaves[hash_index].leaf_script, merkle_path) != self.root:
            raise ValueError("Created merkle path failed to calculate merkle root.")

        return merkle_path

    @staticmethod
    def eval_merkle_path(leaf_script: bytes, merkle_path: bytes) -> bytes:
        """
        Given a leaf_script and merkle path, we create the leaf_hash and calculate the merkle root based on the
        merkle path
        """
        # Verify merkle_path size
        if len(merkle_path) % _tap.HASH_SIZE != 0:
            raise ValueError(f"Merkle path must be divisible by {_tap.HASH_SIZE}")

        # Break merkle_path into 32-byte chunks
        sibling_hashes = [merkle_path[i:i + _tap.HASH_SIZE] for i in range(0, len(merkle_path), _tap.HASH_SIZE)]

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
    leaf_script1 = bytes.fromhex("5187")
    leaf_script2 = bytes.fromhex("5287")
    leaf_script3 = bytes.fromhex("5387")
    leaf_script4 = bytes.fromhex("5487")
    leaf_script5 = bytes.fromhex("5587")

    test_leaves = [leaf_script1, leaf_script2, leaf_script3, leaf_script4, leaf_script5]

    test_tree = ScriptTree(test_leaves, balanced=False)
    test_merkle_path = test_tree.get_merkle_path(leaf_script3)

    balanced_tree = ScriptTree(test_leaves, balanced=True)
    test_balanced_merklepath = balanced_tree.get_merkle_path(leaf_script3)

    # Unbalanced test tree from learnmeabitcoin.com
    print("=== UNBALANCED TREE ===")
    print(f"MERKLE ROOT: {test_tree.root.hex()}")
    print(f"MERKLE PATH: {test_merkle_path.hex()}")
    print(f"LEAF HASHES: {[l.leaf_hash.hex() for l in test_tree.leaves]}")
    print(f"BRANCHES: {[b.branch_hash.hex() for b in test_tree.branches]}")
    print("===" * 80)

    # Balanced tree
    print("=== BALANCED TREE ===")
    print(f"MERKLE ROOT: {balanced_tree.root.hex()}")
    print(f"MERKLE PATH: {test_balanced_merklepath.hex()}")
    print(f"LEAF HASHES: {[l.leaf_hash.hex() for l in balanced_tree.leaves]}")
    print(f"BRANCHES: {[b.branch_hash.hex() for b in balanced_tree.branches]}")
    print("===" * 80)
