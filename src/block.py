"""
Block and MerkleTree classes
"""
import io
import json
import math
import struct

from src.library.data_handling import write_compact_size, read_compact_size, check_length
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


class BlockHeader(Serializable):
    """Represents the 80-byte Bitcoin Block Header"""
    __slots__ = ('version', 'prev_block', 'merkle_root', 'timestamp', 'bits', 'nonce')

    HEADER_FORMAT = "<L32s32sL4sL"  # Little-endian: uint32, 32 bytes, 32 bytes, uint32, 4 bytes, uint32

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
            self.HEADER_FORMAT,
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
        if len(byte_stream) != cls.HEADER_BYTES:
            raise ValueError("Invalid block header size")
        fields = struct.unpack(cls.HEADER_FORMAT, byte_stream)
        return cls(*fields)

    def to_dict(self):
        """Returns a dictionary representation of the block header."""
        return {
            "id": self.block_id[::-1].hex(),  # Reverse for display
            "version": self.version,
            "previous_block": self.prev_block[::-1].hex(),  # Reverse for display
            "merkle_root": self.merkle_root[::-1].hex(),  # Reverse for display
            "timestamp": self.timestamp,
            "bits": self.bits.hex(),
            "nonce": self.nonce,
        }

    @property
    def block_id(self):
        return hash256(self.to_bytes())

    @property
    def block_id_num(self):
        return int.from_bytes(self.block_id, byteorder="little")


class Block(Serializable):
    """
    The Block class for Bitcoin

    Args:
        prev_block (bytes): the block_id of the previous block
        transactions (list): the list of txs to be included in the block
        timestamp (int): unix timestamp for the block
        bits (bytes): bits encoding of the block target
        nonce (int): to affect the block_id
    """
    __slots__ = ('prev_block', 'txs', 'tx_count', 'merkle_tree', 'timestamp', 'bits', 'nonce', 'version')

    def __init__(self, prev_block: bytes, transactions: list, timestamp: int, bits: bytes, nonce: int,
                 version: int = None):
        # Get fixed header values
        self.prev_block = prev_block
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.version = version or self.VERSION

        # Get txs and merkle tree
        self.tx_count = write_compact_size(len(transactions))
        self.txs = transactions
        self.merkle_tree = MerkleTree([tx.txid() for tx in self.txs])

    @classmethod
    def from_bytes(cls, byte_stream):
        if not isinstance(byte_stream, (bytes, io.BytesIO)):
            raise ValueError(f"Expected byte data stream, received {type(byte_stream)}")

        stream = io.BytesIO(byte_stream) if isinstance(byte_stream, bytes) else byte_stream

        # Get header
        _header_bytes = stream.read(cls.HEADER_BYTES)
        check_length(_header_bytes, cls.HEADER_BYTES, "header")
        _header = BlockHeader.from_bytes(_header_bytes)

        # Get txs | handle only header data
        tx_count = read_compact_size(stream)
        txs = []
        for _ in range(0, tx_count):
            temp_tx = Transaction.from_bytes(stream)
            txs.append(temp_tx)

        # Verify merkle root
        temp_tree = MerkleTree([t.txid() for t in txs])
        if temp_tree.merkle_root != _header.merkle_root:
            raise ValueError("Merkle Root mismatch when reconstructing block")

        return cls(_header.prev_block, txs, _header.timestamp, _header.bits, _header.nonce, _header.version)

    @property
    def header(self):
        return BlockHeader(self.version, self.prev_block, self.merkle_tree.merkle_root, self.timestamp, self.bits,
                           self.nonce)

    @property
    def id(self):
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
            "id": self.id[::-1].hex(),  # Reverse bytes for display
            "header": self.header.to_dict(),
            "tx_count": self.tx_count.hex(),
            "txs": [tx.to_dict() for tx in self.txs]
        }
        return block_dict

    def increment(self):
        self.nonce += 1


# -- TESTING
from secrets import randbits, token_bytes

if __name__ == "__main__":
    def get_random_block_header(tx_num: int = 3):
        return BlockHeader(
            version=randbits(32),
            prev_block=token_bytes(32),
            merkle_root=token_bytes(32),
            timestamp=randbits(32),
            bits=token_bytes(4),
            nonce=randbits(32)
        )


    random_header = get_random_block_header()
    print(f"RANDOM HEADER ID: {random_header.block_id.hex()}")
    random_header.increment()
    print(f"RANDOM HEADER NONCE +1: {random_header.block_id.hex()}")
