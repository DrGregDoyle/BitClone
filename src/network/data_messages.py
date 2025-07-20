"""
Data Messages:
    -MerkleBlock
    -CmpctBlock
    -SendCmpct
    -GetBlockTxn

"""
from io import BytesIO

from src.block import Block, BlockHeader, BlockTransactions
from src.data import Inventory, get_stream, read_compact_size, read_stream, write_compact_size, read_little_int, \
    BitcoinFormats
from src.network.messages import DataMessage
from src.tx import Transaction

MB = BitcoinFormats.MagicBytes


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

    def __init__(self, inventory: list[Inventory], magic_bytes: bytes = MB.MAINNET):
        super().__init__(magic_bytes)
        self.magic_bytes = magic_bytes
        self.count = len(inventory)
        self.inventory = inventory

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MB.MAINNET):
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


# ---  GetData Messages --- #

class GetBlockParent(DataMessage):
    """
    The common structure for GetBlocks and GetHeaders
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
                 magic_bytes: bytes = MB.MAINNET):
        super().__init__()
        self.version = version
        self.hash_count = len(locator_hashes)
        self.locator_hashes = locator_hashes
        self.hash_stop = bytes.fromhex("00" * 32) if hash_stop is None else hash_stop
        self.magic_bytes = magic_bytes

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MB.MAINNET):
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
        raise NotImplementedError(f"{self.__class__.__name__} must implement command")

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


class GetBlocks(GetBlockParent):

    @property
    def command(self) -> str:
        return "getblocks"


class GetHeaders(GetBlockParent):
    @property
    def command(self) -> str:
        return "getheaders"


# --- Object Messages --- #

class BlockMessage(DataMessage):
    """
    Will package and send a block
    """

    def __init__(self, block: Block, magic_bytes: bytes = MB.MAINNET):
        super().__init__(magic_bytes)
        self.block = block

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MB.MAINNET):
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
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MB.MAINNET):
        # Use inherent block method
        return Transaction.from_bytes(byte_stream)

    @property
    def command(self) -> str:
        return "tx"

    def payload(self) -> bytes:
        return self.tx.to_bytes()

    def _payload_dict(self) -> dict:
        return self.tx.to_dict()


class HeaderMessage(DataMessage):
    """
    The headers packet returns block headers in response to a getheaders packet.
    -------------------------------------------------
    |   Name    | data type |   format      | size  |
    -------------------------------------------------
    |   count   | int       | CompactSize   | var   |
    |   headers | list      | BlockHeader   | 81x   |
    -------------------------------------------------
    """

    def __init__(self, header_list: list[BlockHeader], magic_bytes: bytes = MB.MAINNET):
        super().__init__()
        self.headers = header_list
        self.count = len(self.headers)
        self.magic_bytes = magic_bytes

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MB.MAINNET):
        stream = get_stream(byte_stream)

        # Get count
        count = read_compact_size(stream, "headers_count")

        # Get headers
        header_list = []
        for _ in range(count):
            temp_header = BlockHeader.from_bytes(stream)
            header_list.append(temp_header)

        return cls(header_list, magic_bytes)

    @property
    def command(self) -> str:
        return "headers"

    def payload(self) -> bytes:
        payload = write_compact_size(self.count)
        for h in self.headers:
            payload += h.to_bytes() + b'\x00'  # 80 byte header + 1 byte tx count set to 0
        return payload

    def _payload_dict(self) -> dict:
        header_dict = {}
        for x in range(self.count):
            header_dict.update({f"header_{x}": self.headers[x].to_dict()})
        payload_dict = {
            "count": self.count,
            "headers": header_dict
        }
        return payload_dict


class MemPool(DataMessage):
    """
    The mempool message sends a request to a node asking for information about transactions it has verified but which
    have not yet confirmed. The response to receiving this message is an inv message containing the transaction
    hashes for all the transactions in the node's mempool.

    No additional data is transmitted with this message.
    """

    @property
    def command(self) -> str:
        return "mempool"

    def payload(self):
        return b''


class BlockTxn(DataMessage):

    def __init__(self, block_tx: BlockTransactions):
        super().__init__()
        self.block_tx = block_tx

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MB.MAINNET):
        stream = get_stream(byte_stream)

        block_tx = BlockTransactions.from_bytes(stream)
        return cls(block_tx)

    @property
    def command(self) -> str:
        return "blocktxn"

    def payload(self) -> bytes:
        return self.block_tx.to_bytes()

    def _payload_dict(self) -> dict:
        return {"block_txn": self.block_tx.to_dict()}


# --- BIP-0152 --- #


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
