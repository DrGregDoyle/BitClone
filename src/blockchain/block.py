"""
The Block classes
"""

import time
from datetime import datetime

from src.core.byte_stream import SERIALIZED, get_stream, read_stream, read_little_int, read_compact_size
from src.core.formats import BLOCK
from src.core.serializable import Serializable
from src.cryptography import hash256
from src.data import bits_to_target, MerkleTree, write_compact_size
from src.tx import Transaction


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

    def __init__(self,
                 version: int = None,
                 prev_block: bytes = None,
                 merkle_root: bytes = None,
                 timestamp: int = None,
                 bits: bytes = None,
                 nonce: int = None
                 ):
        self.version = version or BLOCK.VERSION
        self.prev_block = prev_block or b'\x00' * BLOCK.PREV_BLOCK
        self.merkle_root = merkle_root or b'\x00' * BLOCK.MERKLE_ROOT
        self.timestamp = timestamp or int(time.time())
        self.bits = bits or b'\x00' * BLOCK.BITS
        self.nonce = nonce or 0

    @property
    def block_id(self):
        return hash256(self.to_bytes())

    @property
    def target(self):
        return bits_to_target(self.bits)

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        version = read_little_int(stream, BLOCK.VERSION)
        prev_block = read_stream(stream, BLOCK.PREV_BLOCK)
        merkle_root = read_stream(stream, BLOCK.MERKLE_ROOT)
        timestamp = read_little_int(stream, BLOCK.TIME)
        bits = read_stream(stream, BLOCK.BITS)[::-1]  # Bits is little-endian bytes
        nonce = read_little_int(stream, BLOCK.NONCE)

        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)

    def to_bytes(self) -> bytes:
        parts = [
            self.version.to_bytes(BLOCK.VERSION, "little"),
            self.prev_block,
            self.merkle_root,
            self.timestamp.to_bytes(BLOCK.TIME, "little"),
            self.bits[::-1],  # Little endian serialized
            self.nonce.to_bytes(BLOCK.NONCE, "little")
        ]
        return b''.join(parts)

    def to_dict(self, formatted: bool = True) -> dict:
        return {
            # Formatted block hash reverses byte order for display
            "block_hash": self.block_id[::-1].hex() if formatted else self.block_id.hex(),
            "version": self.version.to_bytes(4, "little").hex() if formatted else self.version,
            "previous_block": self.prev_block[::-1].hex() if formatted else self.prev_block.hex(),
            # Formatted merkle root reverse byte order for display
            "merkle_root": self.merkle_root[::-1].hex() if formatted else self.merkle_root.hex(),
            "timestamp": datetime.fromtimestamp(self.timestamp).strftime(
                BLOCK.TIMESTAMP_FORMAT) if formatted else self.timestamp,
            "bits": self.bits.hex(),
            "nonce": self.nonce.to_bytes(BLOCK.NONCE, "little").hex() if formatted else self.nonce
        }

    def increment(self):
        self.nonce += 1

    # --- TESTING --


class Block(Serializable):
    """
    ---------------------------------------------------------------------
    |   Name        |   data_type   |   format              |   size    |
    ---------------------------------------------------------------------
    |                       BlockHeader                                 |
    ---------------------------------------------------------------------
    |   Version     |   int         |   little-endian       |   4       |
    |   prev_block  |   bytes       |   natural byte order  |   32      |
    |   merkle_root |   bytes       |   natural byte order  |   32      |
    |   time        |   int         |   little-endian       |   4       |
    |   bits        |   bytes       |   little-endian       |   4       |
    |   nonce       |   int         |   little-endian       |   4       |
    ---------------------------------------------------------------------
    |                       Transactions                                |
    ---------------------------------------------------------------------
    |   tx_num      |   int         |   CompactSize         |   var     |
    |   txs         |   list        |   Serializable        |   var     |
    ---------------------------------------------------------------------
    """
    __slots__ = ('prev_block', 'txs', 'tx_num', 'merkle_tree', 'timestamp', 'bits', 'nonce', 'version')

    def __init__(self,
                 version: int = None,
                 prev_block: bytes = None,
                 timestamp: int = None,
                 bits: bytes = None,
                 nonce: int = None,
                 txs: list[Transaction] = None
                 ):
        self.version = version or BLOCK.VERSION
        self.prev_block = prev_block or b'\x00' * BLOCK.PREV_BLOCK
        self.timestamp = timestamp or int(time.time())
        self.bits = bits or b'\x00' * BLOCK.BITS
        self.nonce = nonce or 0
        self.txs = txs
        self.merkle_tree = MerkleTree([t.txid for t in self.txs])

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # Read in block header
        header = BlockHeader.from_bytes(stream)

        # Read in txs
        tx_num = read_compact_size(stream)
        txs = []
        for _ in range(tx_num):
            txs.append(Transaction.from_bytes(stream))

        return cls.from_header(header, txs)

    @classmethod
    def from_header(cls, header: BlockHeader, txs: list[Transaction]):
        return cls(
            version=header.version,
            prev_block=header.prev_block,
            timestamp=header.timestamp,
            bits=header.bits,
            nonce=header.nonce,
            txs=txs
        )

    @property
    def block_id(self):
        return self.get_header().block_id

    def get_header(self) -> BlockHeader:
        """
        Return the block header
        """
        return BlockHeader(
            version=self.version,
            prev_block=self.prev_block,
            merkle_root=self.merkle_tree.merkle_root,
            timestamp=self.timestamp,
            bits=self.bits,
            nonce=self.nonce
        )

    def to_bytes(self) -> bytes:
        tx_num = len(self.txs)
        tx_parts = [write_compact_size(tx_num)]
        for tx in self.txs:
            tx_parts.append(tx.to_bytes())
        return self.get_header().to_bytes() + b''.join(tx_parts)

    def to_dict(self, formatted: bool = True) -> dict:
        tx_num = len(self.txs)
        tx_dict = {
            f"{x}": self.txs[x].to_dict(formatted=formatted) for x in range(tx_num)
        }
        return {
            "header": self.get_header().to_dict(formatted),
            "tx_num": tx_num,
            "txs": tx_dict
        }


if __name__ == "__main__":
    test_block_bytes = bytes.fromhex(
        "02000000a8008de56c7e51598863e8dcdbf72410fa31275ee254b9590000000000000000d0a03183007c4e7941e7c7c9989fd956a89be722ce5e88af4df3631eb40ef12bd7595f538c9d0019e9569678")
    test_block = BlockHeader.from_bytes(test_block_bytes)
    print(f"TEST HEADER: {test_block.to_json()}")
