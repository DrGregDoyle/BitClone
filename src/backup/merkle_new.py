import json
from typing import List, Dict, Union, Optional

from src.library.hash_functions import hash256


class MerkleTree:
    def __init__(self, tx_list: List[bytes], to_hex: bool = False):
        """
        Initializes a MerkleTree object.

        :param tx_list: List of transaction IDs (txids), each 32 bytes in little-endian format.
        :param to_hex: If True, stores the tree with hex-encoded hashes; otherwise, stores raw bytes.
        """
        if not tx_list:
            raise ValueError("Transaction list cannot be empty.")

        self.tx_list = tx_list  # Store the original tx list
        self.to_hex = to_hex  # Whether to store tree in hex
        self.tree = self.build_tree()  # Construct the Merkle tree
        self.merkle_root = self.tree[0][0]  # Root of the tree (single element list)

    def build_tree(self) -> Dict[int, List[Union[bytes, str]]]:
        """
        Builds the Merkle tree and returns it as a dictionary.

        :return: A dictionary where keys represent tree levels (0 = Merkle root),
                 and values are lists of hashes in bytes or hex.
        """
        # Convert txids to big-endian (natural byte order)
        leaf_list = [tx[::-1] for tx in self.tx_list]

        # Determine tree height
        height = 0
        num_leaves = len(leaf_list)
        while num_leaves > 1:
            height += 1
            num_leaves = (num_leaves + 1) // 2  # Round up for odd numbers

        tree = {}
        current_height = height  # Leaves are at max height

        while len(leaf_list) > 1:
            if len(leaf_list) % 2 == 1:
                leaf_list.append(leaf_list[-1])  # Duplicate last element if odd

            tree[current_height] = [leaf.hex() if self.to_hex else leaf for leaf in leaf_list]
            leaf_list = [hash256(leaf_list[i] + leaf_list[i + 1]) for i in range(0, len(leaf_list), 2)]
            current_height -= 1  # Move up in the tree

        tree[0] = [leaf_list[0].hex() if self.to_hex else leaf_list[0]]  # Merkle root
        return tree

    def get_merkle_proof(self, tx_id: bytes) -> Optional[List[Union[bytes, str]]]:
        """
        Generates a Merkle proof for a given transaction ID.

        :param tx_id: The transaction hash (32 bytes, little-endian).
        :return: A list of hashes forming the Merkle proof, or None if tx_id not found.
        """
        current_id = tx_id[::-1]  # Convert to big-endian
        proof = []

        for height in sorted(self.tree.keys(), reverse=True):
            level = self.tree[height]

            # Convert back to bytes if needed
            level = [bytes.fromhex(h) if self.to_hex else h for h in level]

            if current_id not in level:
                return None  # Transaction not found in the tree

            index = level.index(current_id)
            pair_index = index - 1 if index % 2 else index + 1

            if pair_index < len(level):
                proof.append(level[pair_index].hex() if self.to_hex else level[pair_index])

            # Move to the next level
            current_id = hash256(level[index] + level[pair_index]) if pair_index < len(level) else level[index]

        return proof

    @classmethod
    def verify_element(cls, tx_id: bytes, proof: List[Union[bytes, str]], merkle_root: Union[bytes, str]) -> bool:
        """
        Verifies a Merkle proof for a given transaction.

        :param tx_id: The transaction hash (32 bytes, little-endian).
        :param proof: A list of hashes forming the Merkle proof.
        :param merkle_root: The Merkle root hash.
        :return: True if valid, False otherwise.
        """
        current_hash = tx_id[::-1]  # Convert to big-endian

        if isinstance(merkle_root, str):
            merkle_root = bytes.fromhex(merkle_root)
            proof = [bytes.fromhex(p) for p in proof]

        for sibling_hash in proof:
            current_hash = hash256(current_hash + sibling_hash)

        return current_hash == merkle_root

    def to_json(self) -> str:
        """
        Serializes the Merkle tree into a JSON-friendly format.

        :return: JSON string representation of the Merkle tree.
        """
        return json.dumps(self.tree, indent=4)
