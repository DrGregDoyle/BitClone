"""
A module for the Block classes
"""
# --- IMPORTS --- #
import json

from src.encoder_lib import encode_compact_size, encode_byte_format
from src.merkle import create_merkle_tree
from src.utility import hash256


# --- CLASSES --- #

class Header:
    """
    Header Fields
    =====================================================================
    |   field               |   size (bytes)    |   format              |
    =====================================================================
    |   version             |   4               |   little-endian       |
    |   previous block hash |   32              |   natural byte order  |
    |   merkle root         |   32              |   natural byte order  |
    |   timestamp           |   4               |   little-endian       |
    |   bits (target)       |   4               |   little-endian       |
    |   nonce               |   4               |   little-endian       |
    =====================================================================

    """
    HASH_CHARS = 64

    def __init__(self, prev_block: str, merkle_root: str, time: int | str, target: int, nonce: int, version=1):
        """
        Todo: Write function to encode target into bits
        """
        # Get and format variables
        self.version = encode_byte_format(version, "version", True)  # Little Endian
        self.prev_block = prev_block.zfill(self.HASH_CHARS)
        self.merkle_root = merkle_root.zfill(self.HASH_CHARS)
        self.time = encode_byte_format(time, "time", True) if isinstance(time, int) else time  # Little Endian
        self.target = encode_byte_format(target, "target", True) if isinstance(time, int) else target  # Little Endian
        self.nonce = encode_byte_format(nonce, "nonce", True) if isinstance(time, int) else nonce  # Little Endian

    @property
    def encoded(self):
        return self.version + self.prev_block + self.merkle_root + self.time + self.target + self.nonce

    @property
    def id(self):
        return hash256(self.encoded)

    def to_json(self):
        header_dict = {
            "version": self.version,
            "prev_block": self.prev_block,
            "merkle_root": self.merkle_root,
            "time": self.time,
            "target": self.target,
            "nonce": self.nonce
        }
        return json.dumps(header_dict, indent=2)


class Block:
    """
    Block fields
    =====================================================================
    |   field               |   size (bytes)    |   format              |
    =====================================================================
    |   version             |   4               |   little-endian       |
    |   previous block hash |   32              |   natural byte order  |
    |   merkle root         |   32              |   natural byte order  |
    |   timestamp           |   4               |   little-endian       |
    |   bits (target)       |   4               |   little-endian       |
    |   nonce               |   4               |   little-endian       |
    |   tx_count            |   var             |   compactSize         |
    |   tx_list             |   var             |   tx.encoded          |
    =====================================================================
    """

    def __init__(self, prev_block: str, time: int, target: int, nonce: int, tx_list: list, version=1):
        # TXs
        self.tx_count = encode_compact_size(len(tx_list))
        self.tx_list = tx_list
        self.tx_id_list = [tx.id for tx in self.tx_list]

        # Create merkle tree
        self.merkle_tree = create_merkle_tree(self.tx_id_list)
        self.merkle_root = self.merkle_tree.get(0)

        # Create Header
        self.prev_block = prev_block
        self.time = time
        self.target = target
        self.nonce = nonce
        self.version = version
        self.header = Header(self.prev_block, self.merkle_root, self.time, self.target, self.nonce, self.version)

    @property
    def block_hash(self):
        return self.header.id

    @property
    def encoded(self):
        encoded_string = self.header.encoded + self.tx_count
        for tx in self.tx_list:
            encoded_string += tx.encoded
        return encoded_string

    def to_json(self):
        block_dict = {"header": json.loads(self.header.to_json())}
        tx_dict = {}
        for x in range(len(self.tx_list)):
            tx_dict.update({x: json.loads(self.tx_list[x].to_json())})
        block_dict.update({"txs": tx_dict})
        return json.dumps(block_dict, indent=2)


# --- TESTING --- #


if __name__ == "__main__":
    print("Hello world!")
