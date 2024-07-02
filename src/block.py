"""
A module for the Block classes
"""
# --- IMPORTS --- #

import json
from datetime import datetime

from src.encoder_lib import EncodedNum, hash256
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
    |   bits                |   4               |   little-endian*      |
    |   nonce               |   4               |   little-endian       |
    |   tx_count            |   var             |   compactSize         |
    |   tx_list             |   var             |   tx.encoded          |
    =====================================================================
    *bits encoding: the first byte is kept in big-endian order but appended to end of remaining 3 bytes placed in
                    little-endian order
    """
    DEFAULT_VERSION = 1
    DEFAULT_BITS = 0x1d00ffff
    HASH_CHARS = 64
    SMALL_CHARS = 8

    def __init__(self, prev_block: str, tx_list: list, nonce: int, time=None, bits=None, version=None):
        # Previous block_id
        self.prev_block = prev_block

        # Transactions
        # self.tx_count = encode_compact_size(len(tx_list))
        self.tx_count = EncodedNum(len(tx_list), encoding="compact").display
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

        # Bits and version
        self.bits = bits if bits else self.DEFAULT_BITS
        self.version = version if version else self.DEFAULT_VERSION

        # -- Formatting -- #

        # Block hash and merkle root has 64 chars
        self.prev_block.zfill(self.HASH_CHARS)
        self.merkle_root.zfill(self.HASH_CHARS)

        # Nonce, time, and version are 8 char little endian
        self.nonce = format(self.nonce, "08x")[::-1]
        self.time = format(self.time, "08x")[::-1]
        self.version = format(self.version, "08x")[::-1]

        # Bits formatting
        exp = self.bits[:2]  # Big-Endian
        coeff = self.bits[2:][::-1]  # Little-Endian
        self.bits = coeff + exp

    @property
    def header(self):
        return self.version + self.prev_block + self.merkle_root + self.time + self.bits + self.nonce

    @property
    def encoded(self):
        return self.header + self.tx_count + self.tx_data

    @property
    def id(self):
        return hash256(self.header)

    def to_json(self):
        header_dict = {
            "version": self.version,
            "previous_block": self.prev_block,
            "merkle_root": self.merkle_root,
            "time": self.time,
            "bits": self.bits,
            "nonce": self.nonce
        }
        tx_dict = {}
        for x in range(len(self.tx_list)):
            tx_dict.update({x: json.loads(self.tx_list[x].to_json())})
        block_dict = {
            "header": header_dict,
            "txs": tx_dict
        }
        return json.dumps(block_dict, indent=2)

    def get_tx_weight(self):
        total = 0
        for tx in self.tx_list:
            total += tx.weight
        return total
