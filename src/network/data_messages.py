"""
Data Messages:
    -Block
    -GetBlocks
    -GetData
    -GetHeaders
    -Headers
    -Inv
    -MemPool
    -MerkleBlock
    -CmpctBlock
    -SendCmpct
    -GetBlockTxn
    -BlockTxn
    -NotFound
    -Tx
"""
from src.data import MAINNET
from src.network.messages import DataMessage


class Inv(DataMessage):
    """
    -----------------------------------------------------
    |   Name        | data type |   format      | size  |
    -----------------------------------------------------
    |   Count       |   int     | compact size  | var   |
    |   Inventory   | list      | *             | var   |
    -----------------------------------------------------
    """

    def __init__(self, inventory: list, magic_bytes: bytes = MAINNET):
        super().__init__(magic_bytes)
        self.magic_bytes = magic_bytes
        self.count = len(inventory)
        self.inventory = inventory


