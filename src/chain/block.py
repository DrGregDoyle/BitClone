"""
The Block classes
"""

import time
from datetime import datetime

from src.core.byte_stream import SERIALIZED, get_stream, read_stream, read_little_int
from src.core.formats import BLOCK
from src.core.serializable import Serializable
from src.cryptography import hash256
from src.data import bits_to_target
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

    def to_dict(self) -> dict:
        return {
            "version": self.version.to_bytes(4, "little").hex(),
            "previous_block": self.prev_block[::-1].hex(),  # Reverse order for display
            "merkle_root": self.merkle_root[::-1].hex(),  # Reverse order for display
            "timestamp": datetime.fromtimestamp(self.timestamp).strftime(BLOCK.TIMESTAMP_FORMAT),
            "bits": self.bits.hex(),
            "target": bits_to_target(self.bits).hex(),
            "nonce": self.nonce
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
        # self.merkle_root = merkle_root or b'\x00' * BLOCK.MERKLE_ROOT
        self.timestamp = timestamp or int(time.time())
        self.bits = bits or b'\x00' * BLOCK.BITS
        self.nonce = nonce or 0


if __name__ == "__main__":
    test_blockheader_bytes = bytes.fromhex(
        "00000020b1ed6d0d4facad44a4f710a356e21fd55a6c5b3c470e1e000000000000000000d9125472b1a611fd33979466550be6e179a5e890c68020b46d4c007ab4fdbb18ecdfac5c1d072c175a2e9a00")
    test_blockheader = BlockHeader.from_bytes(test_blockheader_bytes)
    print(f"TEST BLOCK HEADER: {test_blockheader.to_json()}")
