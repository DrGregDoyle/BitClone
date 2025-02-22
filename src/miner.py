"""
The Miner class
"""
from src.block import Block
from src.library.data_handling import bits_to_target_int
from src.logger import get_logger

logger = get_logger(__name__)


class Miner:

    def __init__(self):
        self.is_mining = False

    def mine_block(self, block: Block):
        self.is_mining = True

        target = bits_to_target_int(block.bits)

        while block.header.block_id_num > target and self.is_mining:
            block.increment()

        # Mining done or interrupted
        return block if self.is_mining else None

    def stop_mining(self):
        self.is_mining = False
