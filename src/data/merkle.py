"""
We create a base class called MerkleTree - common functions used in all Merkle trees.

We then have two children: BlackTree and TaprootTree; Markle trees designed for their respective purpose.
"""
import json
import math

from src.crypto import hash256, tagged_hash_function, HashType
from src.data import write_compact_size
from src.logger import get_logger

logger = get_logger(__name__)


class MerkleTree:
    """
    A class representing a Merkle tree, used to efficiently and securely verify the integrity of a set of data.

    Attributes:
        height (int): The height of the Merkle tree.
        tree (dict[int, list[bytes]]): Dictionary representing the tree levels with hash values.
        hex_tree (dict[int, list[str]]): Dictionary with hex representations of the tree levels.
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
        self.tree = self._create_tree(id_list)
        self.hex_tree = self._create_hex_tree()
        self.merkle_root = self.tree[0][0]  # Root in little-endian

    def _create_tree(self, id_list: list[bytes]) -> dict[int, list[bytes]]:
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
            return {0: clean_list}

        tree = {}
        for level in range(self.height, 0, -1):  # Stop at level 1, leave root untouched
            if len(clean_list) % 2 != 0:
                clean_list.append(clean_list[-1])  # Duplicate last element if odd

            tree[level] = clean_list
            clean_list = [hash256(clean_list[i] + clean_list[i + 1]) for i in range(0, len(clean_list), 2)]

        tree[0] = clean_list  # Only assign root here

        return tree

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
        target_hash = self._clean_list([target_id])[0]
        proof = []

        for level in range(self.height, 0, -1):
            # Verify hash is in tree
            if target_hash not in self.tree[level]:
                raise ValueError(f"Transaction ID {target_id} not found in Merkle tree.")

            index = self.tree[level].index(target_hash)
            sibling_index = index + 1 if index % 2 == 0 else index - 1
            position = "right" if index % 2 == 0 else "left"

            if sibling_index < len(self.tree[level]):
                proof.append((self.tree[level][sibling_index], position))

            if position == "right":
                target_hash = hash256(target_hash + self.tree[level][sibling_index])
            else:
                target_hash = hash256(self.tree[level][sibling_index] + target_hash)

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
        return [bytes.fromhex(_id) if isinstance(_id, str) else _id for _id in id_list]

    def __repr__(self):
        return json.dumps(self.hex_tree, indent=2)


class ScriptTree:
    """
    A Merkle Tree class for the taproot
    """
    VERSION = 0xc0  # 192
    VERSION_BYTE = b'\xc0'

    def __init__(self, script_list: list[bytes], version: int = 0xc0, linear: bool = False):

        self.version = version
        self.script_list = script_list
        self.leaves = self._get_leaves(script_list)
        self.linear = linear

        self.tree = self._get_tree()
        self.root = self.tree[0]

    def _encode_script(self, script):
        """
        Returns VERSION_BYTE + CompactSize(len(script)) + script
        """
        return self.VERSION_BYTE + write_compact_size(len(script)) + script

    def _get_leaves(self, script_list: list[bytes]):
        """
        We return the list of lexicographically sorted leaf hashes of the given leaf scripts
        """

        encoded_scripts = [self._encode_script(s) for s in script_list]
        hashed_scrips = [tagged_hash_function(es, b"TapLeaf", HashType.SHA256) for es in encoded_scripts]
        return sorted(hashed_scrips)

    def _get_tree(self):
        if not self.leaves:
            raise ValueError("No leaves to construct Taproot Merkle tree.")

        nodes = self.leaves[:]

        if self.linear:
            # Linear tree: combine first two lexicographically, then chain remaining
            while len(nodes) > 1:
                if len(nodes) == 2:
                    a, b = sorted([nodes.pop(0), nodes.pop(0)])
                else:
                    a = nodes.pop(0)
                    b = nodes.pop(0)
                parent = tagged_hash_function(a + b, b"TapBranch", HashType.SHA256)
                nodes.insert(0, parent)
        else:
            # Balanced tree: standard pairwise construction with lexicographic pairing
            nodes = sorted(nodes)
            while len(nodes) > 1:
                next_level = []
                for i in range(0, len(nodes) - 1, 2):
                    a, b = sorted([nodes[i], nodes[i + 1]])
                    parent = tagged_hash_function(a + b, b"TapBranch", HashType.SHA256)
                    next_level.append(parent)
                if len(nodes) % 2 == 1:
                    next_level.append(nodes[-1])
                nodes = next_level

        return nodes

    @staticmethod
    def eval_merkle_path(leaf_hash: bytes, merkle_path: bytes) -> bytes:
        """
        Computes the Merkle root given a leaf hash and its associated merkle path.
        The merkle_path must be a multiple of 32 bytes.
        """
        path_length = len(merkle_path)
        if path_length % 32 != 0:
            raise ValueError("Merkle path must be a multiple of 32 bytes")

        current_hash = leaf_hash

        for i in range(0, path_length, 32):
            node = merkle_path[i:i + 32]

            # Lexicographic order
            pair = current_hash + node if current_hash < node else node + current_hash
            current_hash = tagged_hash_function(pair, b"TapBranch", HashType.SHA256)

        return current_hash

    def get_merkle_path(self, leaf_script: bytes):
        pass


# -- TESTING
if __name__ == "__main__":
    hash_list = [
        bytes.fromhex("5187"),
        bytes.fromhex("5287"),
        bytes.fromhex("5387"),
        bytes.fromhex("5487"),
        bytes.fromhex("5587")
    ]
    test_tree = ScriptTree(script_list=hash_list, linear=True)
    print(test_tree.root.hex())
    for x in range(len(test_tree.leaves)):
        print(f"LEAF: {x + 1}, HASH: {test_tree.leaves[x].hex()}")
