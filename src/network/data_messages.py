"""
Data Messages:
    -GetHeaders
    -Headers
    -MemPool
    -MerkleBlock
    -CmpctBlock
    -SendCmpct
    -GetBlockTxn
    -BlockTxn
    -Tx
"""
from io import BytesIO

from src.block import Block
from src.data import MAINNET, Inventory, get_stream, read_compact_size, read_stream, write_compact_size, read_little_int
from src.network.messages import DataMessage
from src.tx import Transaction


# --- Inv | GetData | NotFound --- #
class InvDataParent(DataMessage):
    """
    Common structure for Inv, GetData and NotFound
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
        stream = get_stream(byte_stream)
        inv_count = read_compact_size(stream, "inventory count")
        inv_list = []
        for _ in range(inv_count):
            inv_bytes = read_stream(stream, cls.INV_BYTES, "inventory")
            inv_list.append(Inventory.from_bytes(inv_bytes))
        return cls(inv_list, magic_bytes)

    @property
    def command(self):
        return self.__class__.command

    def payload(self) -> bytes:
        payload = write_compact_size(self.count)
        for i in self.inventory:
            payload += i.to_bytes()
        return payload

    def _payload_dict(self) -> dict:
        payload_dict = {"count": self.count}
        inv_dict = {x: self.inventory[x].to_dict() for x in range(self.count)}
        payload_dict.update({"inventory": inv_dict})
        return payload_dict


class Inv(InvDataParent):

    @property
    def command(self):
        return "inv"


class GetData(InvDataParent):

    @property
    def command(self):
        return "getdata"


class NotFound(InvDataParent):

    @property
    def command(self):
        return "notfound"


# ---  Remaining Data Messages --- #

class GetBlocks(DataMessage):
    """
    -----------------------------------------------------------------
    |   Name                    | data type |   format      | size  |
    -----------------------------------------------------------------
    |   Version                 |   int     | little-endian |   4   |
    |   Hash count              |   int     | compact size  |   var |
    |   Block locator hashes    |   list    | bytes         |   var |
    |   hash_stop               |   bytes   | bytes         |   32  |
    -----------------------------------------------------------------
    """
    HASH_BYTES = 32
    VERSION_BYTES = 4

    def __init__(self, version: int, locator_hashes: list[bytes], hash_stop: bytes = None,
                 magic_bytes: bytes = MAINNET):
        super().__init__()
        self.version = version
        self.hash_count = len(locator_hashes)
        self.locator_hashes = locator_hashes
        self.hash_stop = bytes.fromhex("00" * 32) if hash_stop is None else hash_stop
        self.magic_bytes = magic_bytes

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MAINNET):
        # Get stream
        stream = get_stream(byte_stream)

        # Get version
        version = read_little_int(stream, cls.VERSION_BYTES, "version")

        # Get locator hashes
        hash_count = read_compact_size(stream, "hash_count")
        hash_list = []
        for x in range(hash_count):
            temp_hash = read_stream(stream, cls.HASH_BYTES, "locator_hash")
            hash_list.append(temp_hash)

        # Get stop_hash
        stop_hash = read_stream(stream, cls.HASH_BYTES, "stop_hash")

        return cls(version, hash_list, stop_hash, magic_bytes)

    @property
    def command(self) -> str:
        return "getblocks"

    def payload(self) -> bytes:
        payload = self.version.to_bytes(self.VERSION_BYTES, "little")
        payload += write_compact_size(self.hash_count)
        payload += b''.join(self.locator_hashes)
        payload += self.hash_stop
        return payload

    def _payload_dict(self) -> dict:
        locator_dict = {}
        for x in range(self.hash_count):
            locator_dict.update({f"locator_hash_{x}": self.locator_hashes[x].hex()})
        payload_dict = {
            "version": self.version,
            "hash_count": self.hash_count,
            "locator_hashes": locator_dict,
            "hash_stop": self.hash_stop.hex()
        }
        return payload_dict


class BlockMessage(DataMessage):
    """
    Will package and send a block
    """

    def __init__(self, block: Block, magic_bytes: bytes = MAINNET):
        super().__init__()
        self.block = block

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MAINNET):
        # Use inherent block method
        return Block.from_bytes(byte_stream)

    @property
    def command(self) -> str:
        return "block"

    def payload(self) -> bytes:
        return self.block.to_bytes()

    def _payload_dict(self) -> dict:
        return self.block.to_dict()


class TxMessage(DataMessage):
    """
    Will package and send a tx
    """

    def __init__(self, tx: Transaction):
        super().__init__()
        self.tx = tx

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MAINNET):
        # Use inherent block method
        return Transaction.from_bytes(byte_stream)

    @property
    def command(self) -> str:
        return "tx"

    def payload(self) -> bytes:
        return self.tx.to_bytes()

    def _payload_dict(self) -> dict:
        return self.tx.to_dict()


# --- TESTING
from src.crypto import hash256
from secrets import token_bytes
from random import randint

if __name__ == "__main__":
    random_version = int.from_bytes(token_bytes(4), "big")
    random_hash_count = randint(1, 10)
    random_locator_hash_list = [hash256(token_bytes(32)) for _ in range(random_hash_count)]

    random_get_blocks = GetBlocks(random_version, random_locator_hash_list)
    print(f"RANDOM GET BLOCKS: {random_get_blocks.to_json()}")
