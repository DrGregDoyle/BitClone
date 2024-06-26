"""
The Blockchain class
"""

# --- IMPORTS --- #
from src.block import Block


# --- CLASSES --- #
class Blockchain:
    MAX_TARGET = 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

    def __init__(self):
        self.chain = []
        self.target = 0

    def add_block(self, candidate_block: Block):
        header = candidate_block.header
        tx_list = candidate_block.tx_list
