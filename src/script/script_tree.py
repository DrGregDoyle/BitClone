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
    We create a serialized leaf from a given leaf_script.
    """
    __slots__ = ("leaf_script", "leaf_hash", "version_byte")

    def __init__(self, leaf_script: bytes, version_byte: bytes = _tap.VERSION_BYTE):
        self.version_byte = version_byte
        self.leaf_script = leaf_script
        self.leaf_hash = tapleaf_hash(leaf_script, version_byte)


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
    __slots__ = ("balanced", "scripts", "leaves", "branches", "root", "_hashes", "_index_by_script")

    def __init__(self, scripts: list[bytes], balanced: bool = True, version_byte: bytes = _tap.VERSION_BYTE):
        self.balanced = balanced
        self.scripts = scripts
        self.leaves = [Leaf(s, version_byte) for s in self.scripts]
        self.branches: list[Branch] = []
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

        # Work with hashes to avoid tiny object churn
        level = [lf.leaf_hash for lf in leaves]
        while len(level) > 1:
            next_level = []
            i = 0
            n = len(level)
            while i < n:
                if i + 1 < n:
                    br = Branch(level[i], level[i + 1])
                    self.branches.append(br)
                    next_level.append(br.branch_hash)
                    i += 2
                else:
                    # carry last hash up (no duplication)
                    next_level.append(level[i])
                    i += 1
            level = next_level
        return level[0]

    def _build_unbalanced_tree(self, leaves: list[Leaf]) -> bytes:
        """
        Unbalanced Merkle:
          - First two leaves form the initial branch.
          - Each subsequent leaf combines with the previous branch to form a new branch.
        Returns the root hash (bytes).
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
        try:
            idx = self.scripts.index(leaf_script)
        except ValueError:
            raise ValueError(f"Given leaf script not in scripts list: {leaf_script!r}")

        leaf_hash = self.leaves[idx].leaf_hash

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
            # Index of target in this level
            try:
                index = current_level.index(target_hash)
            except ValueError:
                raise ValueError("Target hash not found in current level")

            n = len(current_level)

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
        """
        Construct the Merkle path for a leaf in an *unbalanced* (fold-shaped) tree.

        Unbalanced tree construction:
          B0 = Branch(L0, L1)
          B1 = Branch(L2, B0)
          B2 = Branch(L3, B1)
          ...
          Root = Branch(Ln, B{n-2})

        Path rules:
          • If the target is L0 or L1:
              – The first sibling is the *other leaf* from the initial pair.
              – Each subsequent leaf L2, L3, … is then folded in one by one, so
                they are also part of the path.

          • If the target is Lk with k ≥ 2:
              – The first sibling is the *branch root* that existed before Lk
                was folded in (e.g. L2’s sibling is B0, L3’s sibling is B1, etc.).
              – Each later leaf L{k+1}, …, Ln is also part of the path.

        The path is encoded as the concatenation of 32-byte sibling hashes.
        When evaluated with `eval_merkle_path`, the path guarantees that starting
        from the target leaf hash and combining with each sibling in order
        (lexicographically sorted at each branch) will reproduce the stored root.

        This shape is non-canonical for Taproot (which uses balanced taptrees),
        but is useful for testing and for demonstrating inclusion proofs in
        fold-style Merkle constructions.
        """
        # Find the leaf hash index using next() with enumerate
        try:
            k = next(i for i, leaf_obj in enumerate(self.leaves) if leaf_obj.leaf_hash == leaf_hash)
        except StopIteration:
            raise ValueError("Leaf hash not found")

        # Trivial cases:
        n = len(self.leaves)
        if n == 0:
            raise ValueError("Empty tree")
        if n == 1:
            return b''  # no siblings

        # helper accessors
        def L(i: int) -> bytes:
            return self.leaves[i].leaf_hash

        def B(i: int) -> bytes:
            return self.branches[i].branch_hash

        parts: list[bytes] = []

        if k <= 1:
            # sibling from the initial pair
            parts.append(L(1 - k))
            # then each newly added leaf thereafter
            if n > 2:
                parts.extend(L(i) for i in range(2, n))
        else:
            # sibling is the branch built before adding leaf k
            parts.append(B(k - 2))
            # then each newly added leaf thereafter
            if k + 1 < n:
                parts.extend(L(i) for i in range(k + 1, n))

        return b"".join(parts)

    @staticmethod
    def eval_merkle_path(leaf_script: bytes, merkle_path: bytes, version_byte: bytes = _tap.VERSION_BYTE) -> bytes:
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
        current_hash = tapleaf_hash(leaf_script, version_byte)

        # Build merkle root
        for sibling_hash in sibling_hashes:
            current_hash = Branch(current_hash, sibling_hash).branch_hash

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
    balanced_tree = ScriptTree(test_leaves, balanced=True)

    # mp1 = test_tree.get_merkle_path(leaf_script1)
    # mp2 = test_tree.get_merkle_path(leaf_script2)
    # mp3 = test_tree.get_merkle_path(leaf_script3)
    # mp4 = test_tree.get_merkle_path(leaf_script4)
    # mp5 = test_tree.get_merkle_path(leaf_script5)
    #
    # _paths = [mp1, mp2, mp3, mp4, mp5]
    # _scripts = [leaf_script1, leaf_script2, leaf_script3, leaf_script4, leaf_script5]
    #
    # for x in range(len(_paths)):
    #     temp_path = _paths[x]
    #     temp_script = _scripts[x]
    #     calc_root = test_tree.eval_merkle_path(temp_script, temp_path)
    #     print(f"MERKLE PATH {x + 1} SUCCESSFUL: {calc_root == test_tree.root}")
    # print("\n\n")

    # Unbalanced test tree from learnmeabitcoin.com
    print("=== UNBALANCED TREE ===")
    print(f"MERKLE ROOT: {test_tree.root.hex()}")
    print(f"LEAF HASHES: {[l.leaf_hash.hex() for l in test_tree.leaves]}")
    print(f"BRANCHES: {[b.branch_hash.hex() for b in test_tree.branches]}")
    print("===" * 80)

    # Balanced tree
    print("=== BALANCED TREE ===")
    print(f"MERKLE ROOT: {balanced_tree.root.hex()}")
    print(f"LEAF HASHES: {[l.leaf_hash.hex() for l in balanced_tree.leaves]}")
    print(f"BRANCHES: {[b.branch_hash.hex() for b in balanced_tree.branches]}")
    print("===" * 80)
