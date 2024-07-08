"""
A module for the Block and related classes
"""
import json

from src.compact_size import ByteOrder, CompactSize
from src.cryptography import hash256, reverse_bytes
from src.merkle import create_merkle_tree


class Header:
    """
    =========================================================
    |   field       |   size (bytes)|   format              |
    =========================================================
    |   version     |   4           |   little-endian       |
    |   prev_block  |   32          |   natural byte order  |
    |   merkle_root |   32          |   natrual byte order  |
    |   time        |   4           |   little-endian       |
    |   bits        |   4           |   little-endian       |
    |   nonce       |   4           |   little-endian       |
    =========================================================
    """
    PREVBLOCK_BYTES = 32
    MERKLE_BYTES = 32
    TIME_BYTES = 4
    BITS_BYTES = 4
    NONCE_BYTES = 4
    VERSION_BYTES = 4
    VERSION = 2

    def __init__(self, prev_block: str | bytes, merkle_root: str | bytes, time: int | bytes, bits: str | bytes,
                 nonce: int | bytes, version: int | bytes = VERSION):
        # previous block | 32 bytes, natural byte order (little-endian)
        self.prev_block = ByteOrder(prev_block, length=self.PREVBLOCK_BYTES).little

        # merkle root | 32 bytes, natural byte order
        self.merkle_root = ByteOrder(merkle_root, length=self.MERKLE_BYTES).little

        # time | 4 bytes, little-endian
        self.time = ByteOrder(time, length=self.TIME_BYTES).little

        # bits | 4 bytes, little-endian
        self.bits = ByteOrder(bits, length=self.BITS_BYTES).little

        # nonce | 4 bytes, little-endian
        self.nonce = ByteOrder(nonce, length=self.NONCE_BYTES).little

        # version | 4 bytes, little-endian
        self.version = ByteOrder(version, length=self.VERSION_BYTES).little

    @property
    def bytes(self):
        return self.version + self.prev_block + self.merkle_root + self.time + self.bits + self.nonce

    @property
    def hex(self):
        return self.bytes.hex()

    @property
    def id(self):
        return hash256(self.bytes)

    def to_json(self):
        header_dict = {
            "block_hash": reverse_bytes(self.id),  # reverse byte order
            "version": self.version.hex(),
            "prev_block": self.prev_block.hex(),
            "merkle_root": self.merkle_root.hex(),
            "time": self.time.hex(),
            "bits": self.bits.hex(),
            "nonce": self.nonce.hex()
        }
        return json.dumps(header_dict, indent=2)


class Block:
    VERSION = 2  # Default

    def __init__(self, prev_block: str | bytes, transactions: list, time: int, bits: str, nonce: int, version=VERSION):
        # Transactions
        tx_count = len(transactions)
        self.tx_count = CompactSize(tx_count)
        self.txs = transactions

        # Merkle root
        tx_ids = [t.txid.little.hex() for t in self.txs]
        merkle_tree = create_merkle_tree(tx_ids)

        # Header
        self.header = Header(prev_block, merkle_tree.get(0), time, bits, nonce, version)


# --- TESTING
# from tests.utility import random_tx

if __name__ == "__main__":
    pass
    # tx1 = random_tx()
    # tx2 = random_tx()
    # merkle_tree = create_merkle_tree([tx1.txid, tx2.txid])
    # merkle_root = merkle_tree.get(0)
    #
    # prev_block = random_bytes(byte_length=32).hex()
    #
    # time = int(random_bytes().hex(), 16)
    # bits = random_bytes().hex()
    # nonce = int(random_bytes().hex(), 16)
    # version = int(random_bytes().hex(), 16)
    #
    # h = Header(prev_block, merkle_root, time, bits, nonce, version)
    # print(h.to_json())
    # h1 = decode_header(h.bytes)
    # h2 = decode_header(h.hex)
    #
    # assert h1.bytes == h.bytes
    # assert h2.bytes == h.bytes
