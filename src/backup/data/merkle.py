"""
We create a base class called MerkleTree - common functions used in all Merkle trees.

We then have two children: BlackTree and TaprootTree; Markle trees designed for their respective purpose.
"""
import math

from src.backup.crypto import hash256
from src.backup.logger import get_logger

logger = get_logger(__name__)

__all__ = ["MerkleTree"]


class MerkleTree:
    """
    A class representing a Merkle tree, used to efficiently and securely verify the integrity of a set of data.

    Attributes:
        height (int): The height of the Merkle tree.
        tree (dict[int, list[bytes]]): Dictionary representing the tree levels with hash values.
        merkle_root (bytes): The Merkle root in little-endian format.
    """

    def __init__(self, id_list: list[str | bytes]):
        """
        Initializes a Merkle tree from a list of transaction IDs.

        Args:
            id_list (list[str | bytes]): A list of transaction IDs in hexadecimal string or bytes format.
        """
        if not id_list:
            logger.error("Attempted to initialize MerkleTree with an empty list.")
            raise ValueError("ID list cannot be empty. A Merkle tree requires at least one transaction ID.")

        self.height = 0 if len(id_list) == 1 else math.ceil(math.log2(len(id_list)))
        self.tree, self.mutated = self._create_tree(id_list)
        self.hex_tree = self._create_hex_tree()
        self.merkle_root = self.tree[0][0]  # Root in little-endian

    def _create_tree(self, id_list: list[bytes]) -> tuple[dict[int, list[bytes]], bool]:
        """
        Constructs the Merkle tree structure.

        Args:
            id_list (list[bytes]): A cleaned list of transaction IDs in bytes format.

        Returns:
            dict[int, list[bytes]]: A dictionary representing the Merkle tree.
        """
        clean_list = self._clean_list(id_list)

        # If there's only one transaction, the Merkle root is the transaction itself
        if len(clean_list) == 1:
            return {0: clean_list}, False

        tree: dict[int, list[bytes]] = {}
        mutated = False
        for level in range(self.height, 0, -1):  # Stop at level 1, leave root for 0
            orig_len = len(clean_list)
            if orig_len % 2 != 0:
                clean_list.append(clean_list[-1])  # duplicate last if odd (not a mutation)
            tree[level] = clean_list
            next_level: list[bytes] = []
            for i in range(0, len(clean_list), 2):
                left = clean_list[i]
                right = clean_list[i + 1]
                # Set mutated if two distinct siblings are identical (i+1 exists and not the odd-dup case)
                if i + 1 < orig_len and left == right:
                    mutated = True
                next_level.append(hash256(left + right))
            clean_list = next_level
        tree[0] = clean_list  # root

        return tree, mutated

    def _create_hex_tree(self) -> dict[int, list[str]]:
        """
        Creates a hex representation of the Merkle tree.

        Returns:
            dict[int, list[str]]: A dictionary with the hexadecimal representations of the tree levels.
        """
        return {level: [node.hex() for node in nodes] for level, nodes in self.tree.items()}

    def get_merkle_proof(self, target_id: str | bytes) -> list[tuple[bytes, str]]:
        """
        Generates the Merkle proof for a given transaction ID.

        Args:
            target_id (str | bytes): The transaction ID for which the proof is needed.

        Returns:
            list[bytes]: The Merkle proof, consisting of sibling hashes required to verify the target ID.
        """
        target = self._clean_list([target_id])[0]
        leaves = self.tree[self.height]

        try:
            # Compute leaf index once; tolerate duplicates by taking first match.
            idx = next(i for i, h in enumerate(leaves) if h == target)
        except StopIteration:
            raise ValueError(f"Transaction ID {target_id} not found in Merkle tree.")

        proof: list[tuple[bytes, str]] = []
        for level in range(self.height, 0, -1):
            nodes = self.tree[level]
            is_right = (idx % 2 == 1)  # if this node is the right child, sibling is on the left
            sib_idx = idx - 1 if is_right else idx + 1
            if sib_idx >= len(nodes):  # odd-dup case: sibling is the same node
                sib = nodes[idx]
            else:
                sib = nodes[sib_idx]
            proof.append((sib, "left" if is_right else "right"))
            idx //= 2
        return proof

    def verify_merkle_proof(self, proof: list[tuple[bytes, str]], target_id: str | bytes) -> bool:
        """
        Verifies a Merkle proof for a given transaction ID.

        Args:
            proof (list[tuple[bytes, str]]): The Merkle proof, consisting of sibling hashes and their position.
            target_id (str | bytes): The transaction ID to verify.

        Returns:
            bool: True if the proof is valid and reconstructs the Merkle root, False otherwise.
        """
        target_hash = self._clean_list([target_id])[0]

        for sibling_hash, position in proof:
            if position == "right":
                target_hash = hash256(target_hash + sibling_hash)
            else:
                target_hash = hash256(sibling_hash + target_hash)

        if target_hash != self.merkle_root:
            logger.warning(f"Merkle proof verification failed for target ID: {target_id}")
            return False
        return True

    @staticmethod
    def _clean_list(id_list: list[str | bytes]) -> list[bytes]:
        """
        Converts transaction IDs to bytes format.
        """
        out: list[bytes] = []

        for _id in id_list:
            b = bytes.fromhex(_id) if isinstance(_id, str) else _id
            # Check bytes
            if len(b) != 32:
                raise ValueError("All leaves must be 32-byte txids (internal byte order).")
            out.append(b)
        return out

    def __repr__(self):
        return f"MerkleTree(height={self.height}, root={self.merkle_root.hex()}, mutated=" \
               f"{getattr(self, 'mutated', False)})"
