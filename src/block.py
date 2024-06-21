"""
A module for the Block class

    Block Structure
    ======================================================================
    Size                Field                   Description
    ======================================================================
    4 bytes             Block size              The size of the block in bytes
    80 bytes            Block header            Standard Header formatting
    1-3 compactSize     Transaction counter     Number of transactions
    var                 Transactions            The transactions for the block
    ======================================================================
"""
import json
from datetime import datetime

from src.utility import *


# --- IMPORTS --- #


def unix_time():
    return datetime.utcnow().timestamp()[::-1]  # Little Endian


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
    VERSION_BYTES = 4
    HASH_BYTES = 32
    MERKLE_BYTES = 32
    TIME_BYTES = 4
    TARGET_BYTES = 4
    NONCE_BYTES = 4

    def __init__(self, prev_block: str, merkle_root: str, target: int, nonce: int, timestamp: int | None = None,
                 version=1):
        """
        Todo: Write function to encode target into bits
        """
        # Get and format variables
        self.prev_block = prev_block.zfill(2 * self.HASH_BYTES)
        self.merkle_root = merkle_root.zfill(2 * self.MERKLE_BYTES)

        self.target = format(target, f"0{2 * self.TARGET_BYTES}x")[::-1]  # Little Endian
        self.nonce = format(nonce, f"0{2 * self.NONCE_BYTES}x")[::-1]  # Little Endian
        self.version = format(version, f"0{2 * self.VERSION_BYTES}x")[::-1]  # Little Endian

        # Get time
        if timestamp:
            temp_dt = datetime.fromtimestamp(timestamp / 1e3)
            self.time = int(round(temp_dt.utcnow().timestamp()))
        else:
            self.time = unix_time()
        self.time = format(self.time, f"0{2 * self.TIME_BYTES}x")[::-1]  # Little Endian

    @property
    def encoded(self):
        return self.version + self.prev_block + self.merkle_root + self.time + self.target + self.nonce

    @property
    def id(self):
        return sha256(self.encoded.encode()).hexdigest()

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


def decode_header(header_string: str):
    # Get chars
    version_chars = 2 * Header.VERSION_BYTES
    hash_chars = 2 * Header.HASH_BYTES
    merkle_chars = 2 * Header.MERKLE_BYTES
    time_chars = 2 * Header.TIME_BYTES
    target_chars = 2 * Header.TARGET_BYTES
    nonce_chars = 2 * Header.NONCE_BYTES

    # Version
    version = header_string[:version_chars]
    current_index = version_chars
    version_int = int(version[::-1], 16)

    # Previous Block
    prev_block = header_string[current_index:current_index + hash_chars]
    current_index += hash_chars

    # Merkle Root
    merkle_root = header_string[current_index: current_index + merkle_chars]
    current_index += merkle_chars

    # Time
    timestamp = header_string[current_index:current_index + time_chars]
    current_index += time_chars
    timestamp_int = int(timestamp[::-1], 16)

    # target
    target = header_string[current_index:current_index + target_chars]
    current_index += target_chars
    target_int = int(target[::-1], 16)

    # nonce
    nonce = header_string[current_index:current_index + nonce_chars]
    nonce_int = int(nonce[::-1], 16)

    # Verify
    constructed_encoding = version + prev_block + merkle_root + timestamp + target + nonce
    constructed_header = Header(prev_block=prev_block, merkle_root=merkle_root, target=target_int, nonce=nonce_int,
                                timestamp=timestamp_int, version=version_int)
    if constructed_header.encoded != constructed_encoding:
        raise TypeError("Given input string did not generate same Header object")
    return constructed_header


# --- TESTING --- #
if __name__ == "__main__":
    prev_block = random_tx_id()
    merkle_root = random_hash256()
    target = random_integer(4)
    test_time = random_integer(4)
    nonce = random_integer(4)
    print(f"PREV BLOCK: {prev_block}")
    print(f"MERKLE ROOT: {merkle_root}")
    print(f"TARGET: {target}")
    print(f"HEX TARGET: {hex(target)}")
    print(f"TIME: {test_time}")
    print(f"HEX TIME: {hex(test_time)}")
    print(f"NONCE: {nonce}")
    print(f"HEX NONCE: {hex(nonce)}")

    test_header = Header(prev_block=prev_block, merkle_root=merkle_root, target=target, nonce=nonce,
                         timestamp=test_time)
    print(test_header.to_json())
    c_header = decode_header(test_header.encoded)
    print(c_header.to_json())
