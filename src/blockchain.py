"""
The Blockchain class
"""

# --- IMPORTS --- #
from src.block import Block


# --- CLASSES --- #
class Blockchain:

    def __init__(self):
        self.chain = []

    def add_block(self, candidate_block: Block):
        header = candidate_block.header
        tx_list = candidate_block.tx_list
