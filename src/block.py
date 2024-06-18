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

# --- IMPORTS --- #
import time

from src.merkle import MerkleTree
from src.transaction import CompactSize


# --- CLASSES --- #

class Header:
    """
    Format:
        Version  | 4 bytes
        Previous Hash   | 32 bytes
        Merkle Root     | 32 bytes
        Timestamp       | 4 bytes
        Target          | 4 bytes
        Nonce           | 4 bytes
    """

    def __init__(self, prev_hash: str, merkle_root: str, timestamp: time.struct_time, target: int, nonce: int):
        self.prev_hash = prev_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.target = target
        self.nonce = nonce

    def encoded(self):
        return (self.prev_hash.upper() + self.merkle_root.upper() + str(self.timestamp) + str(self.target) +
                str(self.nonce))


class Block:
    def __init__(self, prev_hash: str, timestamp: time.struct_time, target: int, nonce: int, transactions: list):
        # Get Merkle Root
        self.transactions = transactions
        merkle_tree = MerkleTree(self.transactions)
        self.merkle_root = merkle_tree.merkle_root

        # Create Header
        self.header = Header(prev_hash=prev_hash, merkle_root=self.merkle_root, timestamp=timestamp, target=target,
                             nonce=nonce)

        # Create Transaction Counter
        tx_count = CompactSize(len(self.transactions))
