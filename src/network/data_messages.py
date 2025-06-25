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
from io import BytesIO

from src.data import MAINNET, Inventory, get_stream, read_compact_size, read_stream, write_compact_size
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
    INV_BYTES = 36

    def __init__(self, inventory: list[Inventory], magic_bytes: bytes = MAINNET):
        super().__init__(magic_bytes)
        self.magic_bytes = magic_bytes
        self.count = len(inventory)
        self.inventory = inventory

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MAINNET):
        # Get stream
        stream = get_stream(byte_stream)

        # Get count
        inv_count = read_compact_size(stream, "inventory count")

        # Get inv_list
        inv_list = []
        for _ in range(inv_count):
            inv_bytes = read_stream(stream, cls.INV_BYTES, "inventory")
            inv_list.append(Inventory.from_bytes(inv_bytes))

        return cls(inv_list, magic_bytes)

    @property
    def command(self):
        return "inv"

    def payload(self) -> bytes:
        payload = write_compact_size(self.count)
        for i in self.inventory:
            payload += i.to_bytes()
        return payload

    def _payload_dict(self) -> dict:
        payload_dict = {"count": self.count}
        inv_dict = {}
        for x in range(self.count):
            temp_inv = self.inventory[x]
            inv_dict.update({x: temp_inv.to_dict()})
        payload_dict.update({"inventory": inv_dict})
        return payload_dict


# --- TESTING
from src.crypto import hash256
from secrets import token_bytes

if __name__ == "__main__":
    hash1 = hash256(token_bytes(8))
    hash2 = hash256(token_bytes(8))
    inv1 = Inventory(1, hash1)
    inv2 = Inventory(2, hash2)
    test_inv = Inv([inv1, inv2])
    print(f"TEST INV: {test_inv.to_json()}")