"""
The MerkleTree class
"""
import json
from math import ceil, log2

from src.core import MerkleError
from src.cryptography import hash256

__all__ = ["MerkleTree"]


class MerkleTree:
    """
    A class representing a Merkle tree, used to efficiently and securely verify the integrity of a set of data.
    """
    __slots__ = ("height", "tree", "merkle_root")

    def __init__(self, id_list: list[bytes]):
        if not id_list:
            raise MerkleError("ID list cannot be empty. A Merkle tree requires at least one transaction ID.")

        self.height = 0 if len(id_list) == 1 else ceil(log2(len(id_list)))
        self.tree = self._create_tree(id_list)
        self.merkle_root = self.tree[0][0]  # First [0] is dictionary key, second [0] is list element

    def _create_tree(self, id_list: list[bytes]):
        # If there's only one transaction, the Merkle root is the transaction itself
        if len(id_list) == 1:
            return {0: id_list}

        tree = {}
        upper_level = []
        for level in range(self.height, 0, -1):  # Stop at level 1, leave root for 0
            # Get length of list
            list_len = len(id_list)
            # Handle odd case
            if list_len % 2 != 0:
                id_list.append(id_list[-1])
            # Assign list as dictionary level
            tree[level] = id_list
            # Create upper level list
            upper_level = []
            for i in range(0, list_len, 2):
                left = id_list[i]
                right = id_list[i + 1]
                upper_level.append(hash256(left + right))
            id_list = upper_level
        tree[0] = upper_level  # Root

        return tree

    def get_merkle_proof(self, target_id: bytes) -> list[tuple[bytes, str]]:
        """
        Generates the Merkle proof for a given transaction ID.
        """
        # Compute leaf index once; tolerate duplicates by taking first match.
        try:
            idx = next(i for i, h in enumerate(self.tree[self.height]) if h == target_id)
        except StopIteration:
            raise ValueError(f"Transaction ID {target_id} not found in Merkle tree.")

        # Construct proof
        proof = []
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

    def verify_merkle_proof(self, proof: list[tuple[bytes, str]], target_id: bytes):

        target_hash = target_id
        for sibling_hash, position in proof:
            if position == "right":
                target_hash = hash256(target_hash + sibling_hash)
            else:
                target_hash = hash256(sibling_hash + target_hash)

        if target_hash != self.merkle_root:
            # TODO: Remove print statement after debugging
            print(f"Merkle proof verification failed for target ID: {target_id}")
            return False
        return True

    # --- DISPLAY --- #

    def to_dict(self):
        """
        Returns dictionary representation of the tree
        """
        return {level: [node.hex() for node in nodes] for level, nodes in self.tree.items()}

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


# --- TESTING ---
if __name__ == "__main__":
    hex_list = [
        "e2393e26a9cfb6d3d672013a7ec1b42ba91decf2da55478aace05f46ddf440aa",
        "9e33e69ffb8be71b2522defe067ff7099c30c48b756577c33c01f3c6fde61c0c",
        "7cda687e6705d60134662fbfd3a386dce54076bbe33a1af9b83c07b3622d4c98",
        "ee2f9c3a3d81c2b23b1e58d14559213951baae53231ddbcd88926ff69161a031"
    ]
    _id_list = [bytes.fromhex(h) for h in hex_list]
    sample_tree = MerkleTree(_id_list)
    print(f"SAMPLE TREE ROOT: {sample_tree.merkle_root.hex()}")
    print(f"SAMPLE TREE DICT: {sample_tree.to_json()}")
    merkle_proof = sample_tree.get_merkle_proof(bytes.fromhex(
        "7cda687e6705d60134662fbfd3a386dce54076bbe33a1af9b83c07b3622d4c98"))
    print(f"MERKLE PROOF: {[(b.hex(), p) for (b, p) in merkle_proof]}")
    print(
        f"VERIFY MERKLE PROOF: "
        f"{sample_tree.verify_merkle_proof(merkle_proof, bytes.fromhex('7cda687e6705d60134662fbfd3a386dce54076bbe33a1af9b83c07b3622d4c98'))}")
