"""
A class for mining blocks
"""
from src.backup.block import Block
from src.backup.parse import bits_to_target


class Miner:

    def __init__(self):
        self.is_mining = False

    def mine_block(self, candidate_block: Block):
        # Set mining flag
        self.is_mining = True

        # Get block target as hex string
        block_target = bits_to_target(candidate_block.header.bits)

        # Mine block
        while int(candidate_block.header.id, 16) > int(block_target, 16) and self.is_mining:
            candidate_block.header.nonce.increment()

        # Mining done or interrupted
        return candidate_block if self.is_mining else None

    def stop_mining(self):
        self.is_mining = False
