"""
Block and MerkleTree classes
"""
import io
import struct

from src.crypto import hash256
from src.data import Serializable, check_length, read_compact_size, MerkleTree, write_compact_size
from src.logger import get_logger
from src.tx import Transaction

logger = get_logger(__name__)


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

    def increment(self):
        self.nonce += 1


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

    def __init__(self, prev_block: bytes, transactions: list[Transaction], timestamp: int, bits: bytes, nonce: int,
                 version: int = None):
        # Get fixed header values
        self.prev_block = prev_block
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.version = version or self.VERSION

        # Get txs and merkle tree
        self.tx_count = len(transactions)
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
        return self.header.to_bytes() + write_compact_size(self.tx_count) + tx_serial

    def to_dict(self):

        block_dict = {
            "id": self.id[::-1].hex(),  # Reverse bytes for display
            "header": self.header.to_dict(),
            "tx_count": write_compact_size(self.tx_count).hex(),
            "txs": [tx.to_dict() for tx in self.txs]
        }
        return block_dict

    def increment(self):
        self.nonce += 1


# --- TESTING
if __name__ == "__main__":
    test_header = BlockHeader.from_bytes(bytes.fromhex(
        "01000000d4c87e278279e3d4ef8084eef377dbbea2152457d3502c6bb50c0000000000005c5a279737f23e3376595d5f4dfbaf88664421ce21820a00592c13780323aa83338bfe4d8521131a0412de7a"))
    print(f"TEST HEADER: {test_header.to_json()}")

    test_block = Block.from_bytes(bytes.fromhex(
        "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"))
    print(f"GENESIS BLOCK: {test_block.to_json()}")
