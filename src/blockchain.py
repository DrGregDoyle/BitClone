"""
The Blockchain class
"""

# --- IMPORTS --- #

from src.block import Block
from src.database import Database
from src.parse import bits_to_target

MAX_TARGET = 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF


# --- CLASSES --- #
class Blockchain:
    INITIAL_BLOCK_SUBSIDY = 50 * pow(10, 8)
    HALVING_NUMBER = 210000

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
        block_target = bits_to_target(_block.header.bits)
        if int(block_target, 16) < int(_block.header.id, 16):
            error_msg = "Block ID larger than target"
            return False, error_msg

    def calculate_block_subsidy(self):
        halving_exp = 0
        halving_height = 0
        while halving_height < self.height:
            halving_height += self.HALVING_NUMBER
            halving_exp += 1
        return self.INITIAL_BLOCK_SUBSIDY // pow(2, halving_exp)


# --- TESTING
if __name__ == "__main__":
    bc = Blockchain()
    print(bc.INITIAL_BLOCK_SUBSIDY)
    print(bc.calculate_block_subsidy())
