"""
The Blockchain class
"""

# --- IMPORTS --- #
import logging
import sys

from src.block import Block
from src.database import Database
from src.parse import bits_to_target

MAX_TARGET = 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

log_level = logging.DEBUG
logger = logging.getLogger(__name__)
logger.setLevel(log_level)
logger.addHandler(logging.StreamHandler(stream=sys.stdout))


# --- CLASSES --- #
class Blockchain:

    def __init__(self):
        self.chain = []
        self.height = 0
        self.utxos = Database()

    def add_block(self, candidate_block: Block):
        # Validate block
        block_validated = self.validate_block(candidate_block)
        # Add block
        self.chain.append(candidate_block)

        # Update UTXOs / Process Transactions

        # Return True/False

    def validate_block(self, _block: Block):
        # Verify block_id is smaller than target
        block_target = bits_to_target(_block.bits)
        if int(block_target, 16) < int(_block.id, 16):
            logger.error("Block ID larger than target")
            return False
