"""
Block and MerkleTree classes
"""
import io
import json
import math
import struct

from src.library.data_handling import write_compact_size, read_compact_size, from_little_bytes
from src.library.hash_functions import hash256
from src.library.serializable import Serializable
from src.logger import get_logger
from src.tx import Transaction

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
                logger.warning(f"Transaction ID not found in Merkle tree: {target_id}")
                return []

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
        Converts a list of transaction IDs to bytes. We assume the tx_ids are given in the internal byte
        representation.

        Args:
            id_list (list[str | bytes]): List of transaction IDs.

        Returns:
            list[bytes]: List of internal byte order transaction IDs.

        Raises:
            ValueError: If an ID is not a valid hex string or bytes object.
        """
        clean_list = []
        for _id in id_list:
            try:
                _bytesid = bytes.fromhex(_id) if isinstance(_id, str) else _id
                if not isinstance(_bytesid, bytes):
                    raise ValueError(f"Invalid ID type: {_id}")
            except ValueError as e:
                logger.error(f"Error converting transaction ID to bytes: {_id}. Error: {e}")
                raise

            clean_list.append(_bytesid)  # Reverse byte order
        return clean_list

    def __repr__(self):
        return json.dumps(self.hex_tree, indent=2)


class BlockHeader(Serializable):
    """Represents the 80-byte Bitcoin Block Header"""

    # Byte values
    VERSION_BYTES = 4
    BLOCKID_BYTES = 32
    MERKLEROOT_BYTES = 32
    TIME_BYTES = 4
    BITS_BYTES = 4
    NONCE_BYTES = 4

    FORMAT = "<L32s32sL4sL"  # Little-endian: uint32, 32 bytes, 32 bytes, uint32, 4 bytes, uint32
    HEADER_SIZE = 80  # 4 + 32 + 32 + 4 + 4 + 4

    def __init__(self, version: int, prev_block: bytes, merkle_root: bytes, timestamp: int, bits: bytes, nonce: int):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce

    def to_bytes(self):
        """Serializes the block header into an 80-byte binary format."""
        return struct.pack(
            self.FORMAT,
            self.version,
            self.prev_block,
            self.merkle_root,
            self.timestamp,
            self.bits,
            self.nonce,
        )

    @classmethod
    def from_bytes(cls, byte_stream):
        """Deserializes an 80-byte block header."""
        if len(byte_stream) != cls.HEADER_SIZE:
            raise ValueError("Invalid block header size")
        fields = struct.unpack(cls.FORMAT, byte_stream)
        return cls(*fields)

    def hash(self):
        """Computes the double SHA-256 hash of the block header."""
        return hash256(self.to_bytes())

    def to_dict(self):
        """Returns a dictionary representation of the block header."""
        return {
            "version": self.version,
            "previous_block": self.prev_block[::-1].hex(),  # Reverse for display
            "merkle_root": self.merkle_root[::-1].hex(),  # Reverse for display
            "timestamp": self.timestamp,
            "bits": self.bits[::-1].hex(),  # Reverse for display
            "nonce": self.nonce,
        }


class Block(Serializable):
    # Constants |
    VERSION = 2  # Default
    HEADER_SIZE = 80  # 4 + 32 + 32 + 4 + 4 + 4

    # Struct Formatting
    HEADER_FORMAT = "<L32s32sLLL"  # Little-endian: uint32, 32 bytes, 32 bytes, uint32, uint32, uint32

    # Byte values
    VERSION_BYTES = 4
    BLOCKID_BYTES = 32
    MERKLEROOT_BYTES = 32
    TIME_BYTES = 4
    BITS_BYTES = 4
    NONCE_BYTES = 4

    def __init__(self, prev_block: bytes, transactions: list, timestamp: int, bits: bytes, nonce: int,
                 version=VERSION):

        # First get transactions and the merkle root
        self.tx_count = write_compact_size(len(transactions))
        self.txs = transactions
        self.merkle_tree = MerkleTree([tx.txid() for tx in self.txs])

        # Get Header from remaining values
        self.header = BlockHeader(version, prev_block, self.merkle_tree.merkle_root, timestamp, bits, nonce)

    @classmethod
    def from_bytes(cls, byte_stream):
        if not isinstance(byte_stream, (bytes, io.BytesIO)):
            raise ValueError(f"Expected byte data stream, received {type(byte_stream)}")

        stream = io.BytesIO(byte_stream) if isinstance(byte_stream, bytes) else byte_stream

        # Get byte values
        version = stream.read(cls.VERSION_BYTES)
        block_id = stream.read(cls.BLOCKID_BYTES)
        merkle_root = stream.read(cls.MERKLEROOT_BYTES)
        block_time = stream.read(cls.TIME_BYTES)
        bits = stream.read(cls.BITS_BYTES)
        nonce = stream.read(cls.NONCE_BYTES)

        # Get txs | handle only header data
        tx_count = read_compact_size(stream)
        txs = []
        for _ in range(0, tx_count):
            temp_tx = Transaction.from_bytes(stream)
            txs.append(temp_tx)

        # Convert values
        version_int = from_little_bytes(version)
        time_int = from_little_bytes(block_time)
        nonce_int = from_little_bytes(nonce)

        # Verify merkle root

        temp_tree = MerkleTree([t.txid() for t in txs])
        if temp_tree.merkle_root != merkle_root:
            logger.debug(f"DECODED MERKLE ROOT: {merkle_root.hex()}")
            logger.debug(f"CONSTRUCTED MERKLE ROOT: {temp_tree.merkle_root.hex()}")
            raise ValueError("Merkle Root mismatch when reconstructing block")

        return cls(block_id, txs, time_int, bits, nonce_int, version_int)

    @property
    def hash(self):
        return hash256(self.header.to_bytes())

    def to_bytes(self) -> bytes:
        """
        Format block for serialization
        """
        # Get tx serialized
        tx_serial = b""
        for tx in self.txs:
            tx_serial += tx.to_bytes()

        # Return serialization
        return self.header.to_bytes() + self.tx_count + tx_serial

    def to_dict(self):

        block_dict = {
            "hash": self.hash[::-1].hex(),  # Reverse bytes for display
            "header": self.header.to_dict(),
            "tx_count": self.tx_count.hex(),
            "txs": [tx.to_dict() for tx in self.txs]
        }
        return block_dict


# -- TESTING
if __name__ == "__main__":
    test_ids = ["0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"]
    correct_order_ids = [bytes.fromhex(t)[::-1] for t in test_ids]
    test_tree = MerkleTree(correct_order_ids)
    print(f"MERKLE ROOT: {test_tree.merkle_root.hex()}")

    block_hex = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e362990101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000"
    test_block = Block.from_hex(block_hex)
    new_block = Block.from_hex(test_block.to_bytes().hex())
    print(f"TEST BLOCK: {test_block}")
    print(f"TEST BLOCK AGREES WITH NEW BLOCK: {test_block.to_bytes() == new_block.to_bytes()}")
    test_tx_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000"
    test_tx = Transaction.from_hex(test_tx_hex)
    test_merkle_tree = MerkleTree([test_tx.txid()])
    print(test_merkle_tree.hex_tree)

    header_hex = "04400020861bccb3550a0b639ad912670417c69ddcb64acc39ba02000000000000000000768fd7217bd2948952c8b04edbdf8b034a0c241bdc8121090f2117d09fe5c45483d8b862cc840917f6da3c6c"
    test_header = BlockHeader.from_hex(header_hex)
    print(test_header)
