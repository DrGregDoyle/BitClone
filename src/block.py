"""
A module for the Block and related classes
"""
import json

from src.library.hash_func import hash256
from src.merkle import create_merkle_tree
from src.parse import bits_to_target, reverse_bytes
from src.predicates import ByteOrder, Endian, CompactSize


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
    NONCE_BYTES = 4
    BITS_BYTES = 4
    VERSION_BYTES = 4

    def __init__(self,
                 previous_block: str | bytes,  # Given in natural byte order
                 merkle_root: str | bytes,  # Given in natural byte order
                 time: int,  # 4 bytes | little-endian
                 bits: str,  # 4 bytes | bits-encoding,
                 nonce: int,  # 4 bytes | little-endian,
                 version: int  # 4 bytes | little-endian
                 ):
        self.previous_block = ByteOrder(previous_block)
        self.merkle_root = ByteOrder(merkle_root)
        self.time = Endian(time, self.TIME_BYTES)
        self.bits = bits
        self.nonce = Endian(nonce, self.NONCE_BYTES)
        self.version = Endian(version, self.VERSION_BYTES)

    @property
    def bytes(self):
        _bits = bytes.fromhex(self.bits)
        return (self.version.bytes + self.previous_block.bytes + self.merkle_root.bytes + self.time.bytes + _bits
                + self.nonce.bytes)

    @property
    def hex(self):
        return self.bytes.hex()

    @property
    def id(self):  # natural byte order
        return hash256(self.bytes)

    @property
    def hash(self):
        return ByteOrder(self.id).hex

    def to_json(self):
        header_dict = {
            "block_hash": reverse_bytes(self.id),  # reverse byte order for display
            "version": self.version.hex,
            "prev_block": self.previous_block.hex,
            "merkle_root": reverse_bytes(self.merkle_root.hex),  # reverse byte order for display
            "time": self.time.hex,
            "bits": self.bits,
            "nonce": self.nonce.hex
        }
        return json.dumps(header_dict, indent=2)


class Block:
    VERSION = 2  # Default

    def __init__(self,
                 previous_block: str | bytes,  # Given in Natural Byte Order
                 transactions: list,  # list of Transaction objects,
                 time: int,  # 4 byte unix timestamp
                 bits: str,  # 4 byte - bits-encoding
                 nonce: int,  # 4 byte | little-endian
                 version=VERSION
                 ):
        # Transactions
        self.tx_count = CompactSize(len(transactions))
        self.txs = transactions

        # Merkle Root
        tx_ids = [t.txid for t in self.txs]
        merkle_root = create_merkle_tree(tx_ids).get(0)

        # Header
        self.header = Header(previous_block=previous_block, merkle_root=merkle_root, time=time, bits=bits, nonce=nonce,
                             version=version)

    @property
    def bytes(self):
        tx_data = bytes()
        for t in self.txs:
            tx_data += t.bytes
        return self.header.bytes + self.tx_count.bytes + tx_data

    @property
    def hex(self):
        return self.bytes.hex()

    @property
    def target(self):
        return bits_to_target(self.header.bits)

    @property
    def id(self):
        return self.header.id

    def to_json(self):
        tx_dict = {"tx_count": self.tx_count.hex}
        for x in range(self.tx_count.num):
            temp_tx = self.txs[x]
            tx_dict.update({x: json.loads(temp_tx.to_json())})
        block_dict = {"header": json.loads(self.header.to_json()), "transactions": tx_dict}
        return json.dumps(block_dict, indent=2)


# --- TESTING
if __name__ == "__main__":
    pass
