"""
A module for the Block classes
"""
# --- IMPORTS --- #

import json
from datetime import datetime
from hashlib import sha256

from src.encoder_lib import encode_compact_size
from src.merkle import create_merkle_tree


# --- CLASSES --- #
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
    DEFAULT_VERSION = 1
    DEFAULT_TARGET = 0xFF00FF00
    HASH_CHARS = 64
    SMALL_CHARS = 8

    def __init__(self, prev_block: str, tx_list: list, nonce: int, time=None, target=None, version=None):
        # Previous block_id
        self.prev_block = prev_block

        # Transactions
        self.tx_count = encode_compact_size(len(tx_list))
        self.tx_list = tx_list
        self.tx_data = "".join([tx.encoded for tx in self.tx_list])
        self.tx_id_list = [tx.id for tx in self.tx_list]

        # Get merkle root from tx_id_list
        merkle_tree = create_merkle_tree(self.tx_id_list)
        self.merkle_root = merkle_tree.get(0)

        # Nonce
        self.nonce = nonce

        # Time as unix timestamp
        self.time = time if time else datetime.now().timestamp()

        # Target and version
        self.target = target if target else self.DEFAULT_TARGET
        self.version = version if version else self.DEFAULT_VERSION

        # -- Formatting -- #

        # Block hash and merkle root has 64 chars
        self.prev_block.zfill(self.HASH_CHARS)
        self.merkle_root.zfill(self.HASH_CHARS)

        # Nonce, time, target and version are 8 char little endian
        self.nonce = format(self.nonce, "08x")[::-1]
        self.time = format(self.time, "08x")[::-1]
        self.target = format(self.target, "08x")[::-1]
        self.version = format(self.version, "08x")[::-1]

    @property
    def header(self):
        return self.version + self.prev_block + self.merkle_root + self.time + self.target + self.nonce

    @property
    def encoded(self):
        return self.header + self.tx_count + self.tx_data

    @property
    def id(self):
        return sha256(self.header.encode()).hexdigest()

    def to_json(self):
        header_dict = {
            "version": self.version,
            "previous_block": self.prev_block,
            "merkle_root": self.merkle_root,
            "time": self.time,
            "target": self.target,
            "nonce": self.nonce
        }
        tx_dict = {}
        tx_num = len(self.tx_list)
        for x in range(tx_num):
            tx_dict.update({x: json.loads(self.tx_list[x].to_json())})
        block_dict = {
            "header": header_dict,
            "txs": tx_dict
        }
        return json.dumps(block_dict, indent=2)


# --- TESTING --- #


if __name__ == "__main__":
    print("Hello world!")
