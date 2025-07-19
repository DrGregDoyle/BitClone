"""
Block and MerkleTree classes
"""

from io import BytesIO

from src.crypto import hash256
from src.data import BitcoinFormats
from src.data import Serializable, read_compact_size, MerkleTree, write_compact_size, get_stream, \
    read_stream, read_little_int
from src.logger import get_logger
from src.tx import Transaction

logger = get_logger(__name__)

# alias the nested classese for formatting
BFB = BitcoinFormats.Block
BFP = BitcoinFormats.Protocol


class BlockHeader(Serializable):
    """
    ---------------------------------------------------------------------
    |   Name        |   data_type   |   format              |   size    |
    ---------------------------------------------------------------------
    |   Version     |   int         |   little-endian       |   4       |
    |   prev_block  |   bytes       |   natural byte order  |   32      |
    |   merkle_root |   bytes       |   natural byte order  |   32      |
    |   time        |   int         |   little-endian       |   4       |
    |   bits        |   bytes       |   little-endian       |   4       |
    |   nonce       |   int         |   little-endian       |   4       |
    ---------------------------------------------------------------------
    """
    __slots__ = ('version', 'prev_block', 'merkle_root', 'timestamp', 'bits', 'nonce')

    def __init__(self, version: int, prev_block: bytes, merkle_root: bytes, timestamp: int, bits: bytes, nonce: int):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce

    def to_bytes(self):
        parts = [
            self.version.to_bytes(BFB.VERSION, "little"),
            self.prev_block,
            self.merkle_root,
            self.timestamp.to_bytes(BFB.TIMESTAMP, "little"),
            self.bits,
            self.nonce.to_bytes(BFB.NONCE, "little")
        ]
        return b''.join(parts)

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        stream = get_stream(byte_stream)

        version = read_little_int(stream, BFB.VERSION, "version")
        prev_block = read_stream(stream, BFB.PREVIOUS_HASH, "prev_block")
        merkle_root = read_stream(stream, BFB.MERKLE_ROOT, "merkle_root")
        timestamp = read_little_int(stream, BFB.TIMESTAMP, "Unix epoch time")
        bits = read_stream(stream, BFB.BITS, "bits")
        nonce = read_little_int(stream, BFB.NONCE, "nonce")

        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)

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
        self.version = version or BFP.VERSION

        # Get txs and merkle tree
        self.tx_count = len(transactions)
        self.txs = transactions
        self.merkle_tree = MerkleTree([tx.txid() for tx in self.txs])

    @classmethod
    def from_bytes(cls, byte_stream):
        stream = get_stream(byte_stream)

        # Get header
        header_data = read_stream(stream, BFB.HEADER, "block_header")
        header = BlockHeader.from_bytes(header_data)

        # Get txs | handle only header data
        tx_count = read_compact_size(stream, "Block.tx_count")
        txs = []
        for _ in range(0, tx_count):
            temp_tx = Transaction.from_bytes(stream)
            txs.append(temp_tx)

        # Verify merkle root
        temp_tree = MerkleTree([t.txid() for t in txs])
        if temp_tree.merkle_root != header.merkle_root:
            raise ValueError("Merkle Root mismatch when reconstructing block")

        return cls(header.prev_block, txs, header.timestamp, header.bits, header.nonce, header.version)

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


class BlockTransactions(Serializable):
    """
    Added in protocol version 70014 as described by BIP152.
    ---------------------------------------------------------------------
    |   Name        |	Data Type   | Byte Format           |   Size    |
    ---------------------------------------------------------------------
    |   block_hash  | bytes         |   natural_byte_order  |   32      |
    |   tx_num      |   int         |   CompactSize         |   varint  |
    |   txs         |   list        |   tx.to_bytes()       |   var     |
    ---------------------------------------------------------------------
    """
    BLOCKHASH_BYTES = 32

    def __init__(self, block_hash: bytes, txs: list[Transaction]):
        self.block_hash = block_hash
        self.txs = txs
        self.tx_num = len(txs)

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        stream = get_stream(byte_stream)

        # Get hash
        block_hash = read_stream(stream, cls.BLOCKHASH_BYTES, "block_hash")

        # Get txs
        tx_num = read_compact_size(stream, "BlockTransactions.tx_num")
        txs = [Transaction.from_bytes(stream) for _ in range(tx_num)]

        return cls(block_hash, txs)

    def to_bytes(self) -> bytes:
        tx_bytes = b''.join([tx.to_bytes() for tx in self.txs])
        return self.block_hash + write_compact_size(self.tx_num) + tx_bytes

    def to_dict(self) -> dict:
        blocktx_dict = {
            "block_hash": self.block_hash[::-1].hex(),  # Reverse for display
            "tx_num": self.tx_num,
            "txs": {f"tx_{x}": self.txs[x].to_dict() for x in range(self.tx_num)}
        }
        return blocktx_dict


# --- TESTING


if __name__ == "__main__":
    # notype
    genesis_bytes = bytes.fromhex(
        "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000")  # notype
    genesis_block = Block.from_bytes(genesis_bytes)
    print(f"GENESIS BLOCK: {genesis_block.to_json()}")
