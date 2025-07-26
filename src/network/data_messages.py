"""
Data Message Classes

The following network messages all request or provide data related to transactions and blocks:
    -block
    -blocktxn
    -cmpctblock

    -getblocks
    -getblocktxn
    -getdata
    -getheaders

    -headers
    -inv
    -mempool

    -merkleblock
    -notfound
    -sendcmpct
    -tx

*For block and tx we have appended Msg to distinguish from its data couterpart
"""
from io import BytesIO

from src.block import Block, BlockTransactions, BlockTransactionsRequest, BlockHeader
from src.data import Inventory, get_stream, read_compact_size, read_stream, write_compact_size, read_little_int, \
    BitcoinFormats, little_bytes_to_binary_string
from src.network.message import Message
from src.tx import Transaction, PrefilledTransaction

BF = BitcoinFormats.Message
__all__ = ["BlockMsg", "BlockTxn", "CmpctBlock", "GetBlocks", "GetBlockTxn", "GetData", "GetHeaders", "Headers", "Inv",
           "MemPool", "MerkleBlock", "NotFound", "SendCompact", "TxMsg"]


# --- PARENT CLASSES FOR SIMILAR MESSAGES --- #
class InvParent(Message):
    """
    Common structure for Inv, GetData and NotFound
    -----------------------------------------------------
    |   Name        | data type |   format      | size  |
    -----------------------------------------------------
    |   Count       |   int     | compact size  | var   |
    |   Inventory   | list      | *             | var   |
    -----------------------------------------------------
    """

    def __init__(self, inventory: list[Inventory]):
        super().__init__()
        self.count = len(inventory)
        self.inventory = inventory

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        stream = get_stream(byte_stream)
        inv_count = read_compact_size(stream, "inventory count")
        inv_list = []
        for _ in range(inv_count):
            inv_bytes = read_stream(stream, BF.INV, "inventory")
            inv_list.append(Inventory.from_bytes(inv_bytes))
        return cls(inv_list)

    @property
    def command(self):
        return self.__class__.command

    def payload(self) -> bytes:
        payload = write_compact_size(self.count)
        for i in self.inventory:
            payload += i.to_bytes()
        return payload

    def payload_dict(self) -> dict:
        return {
            "count": self.count,
            "inventory": {f"inv_{x}": self.inventory[x].to_dict() for x in range(self.count)}
        }


class GetBlockParent(Message):
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

    def __init__(self, version: int, locator_hashes: list[bytes], hash_stop: bytes = None):
        super().__init__()
        self.version = version
        self.hash_count = len(locator_hashes)
        self.locator_hashes = locator_hashes
        self.hash_stop = bytes.fromhex("00" * 32) if hash_stop is None else hash_stop

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        # Get stream
        stream = get_stream(byte_stream)

        # Get version
        version = read_little_int(stream, BF.PROTOCOL_VERSION, "version")

        # Get locator hashes
        hash_count = read_compact_size(stream, "hash_count")
        hash_list = []
        for x in range(hash_count):
            temp_hash = read_stream(stream, BF.BLOCKTXHASH, "locator_hash")
            hash_list.append(temp_hash)

        # Get stop_hash
        stop_hash = read_stream(stream, BF.BLOCKTXHASH, "stop_hash")

        return cls(version, hash_list, stop_hash)

    @property
    def command(self) -> str:
        raise NotImplementedError(f"{self.__class__.__name__} must implement command")

    def payload(self) -> bytes:
        payload = self.version.to_bytes(BF.PROTOCOL_VERSION, "little")
        payload += write_compact_size(self.hash_count)
        payload += b''.join(self.locator_hashes)
        payload += self.hash_stop
        return payload

    def payload_dict(self) -> dict:
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


# --- DATA MESSAGES --- #

class BlockMsg(Message):
    """
    Will package and send a block
    """

    def __init__(self, block: Block):
        super().__init__()
        self.block = block

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        # Use inherent block method
        return cls(Block.from_bytes(byte_stream))

    @property
    def command(self) -> str:
        return "block"

    def payload(self) -> bytes:
        return self.block.to_bytes()

    def payload_dict(self) -> dict:
        return self.block.to_dict()


class BlockTxn(Message):
    """
    The BlockTxn message sends a BlockTransactions data structure, as described by BIP152.
    """

    def __init__(self, block_tx: BlockTransactions):
        super().__init__()
        self.block_tx = block_tx

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        stream = get_stream(byte_stream)

        block_tx = BlockTransactions.from_bytes(stream)
        return cls(block_tx)

    @property
    def command(self) -> str:
        return "blocktxn"

    def payload(self) -> bytes:
        return self.block_tx.to_bytes()

    def payload_dict(self) -> dict:
        return {"block_txn": self.block_tx.to_dict()}


class CmpctBlock(Message):
    """
    ---------------------------------------------------------------------------------------------------------
    |   Name                    |	Data Type   | Byte Format                       |   Size                |
    ---------------------------------------------------------------------------------------------------------
    |   block_header            |   Blockheader |   block_header.to_bytes()         |   80                  |
    |   nonce                   |   int         |   little-endian                   |   8                   |
    |   shortids_length         |   int         |   CompactSize                     |   varint              |
    |   shortids                |   list        |   6-byte int with 2-null bytes    |   8*shortids_length   |
    |   prefilled_tx_length     |   int         |   CompactSize                     |   varint              |
    |   prefilled_txs           |   list        |   PrefilledTxn.to_bytes()         |   var                 |
    ---------------------------------------------------------------------------------------------------------
    """

    def __init__(self, header: BlockHeader, nonce: int, shortids: list[bytes],
                 prefilled_txs: list[PrefilledTransaction]):
        super().__init__()
        self.header = header
        self.nonce = nonce
        self.shortids_length = len(shortids)
        self.shortids = shortids
        self.prefilled_tx_length = len(prefilled_txs)
        self.prefilled_txs = prefilled_txs

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        stream = get_stream(byte_stream)

        # header
        header = BlockHeader.from_bytes(stream)

        # nonce
        nonce = read_little_int(stream, BF.CMPCT_NONCE, "nonce")

        # shortids
        shortids_length = read_compact_size(stream, "shortids_length")
        shortids = [read_stream(stream, BF.SHORTID, "shortids") for _ in range(shortids_length)]

        # prefilled_txs
        prefilled_tx_length = read_compact_size(stream, "prefilled_tx_length")
        prefilled_txs = [PrefilledTransaction.from_bytes(stream) for _ in range(prefilled_tx_length)]

        return cls(header, nonce, shortids, prefilled_txs)

    @property
    def command(self) -> str:
        return "cmpctblock"

    def payload(self) -> bytes:
        parts = [
            self.header.to_bytes(),
            self.nonce.to_bytes(BF.CMPCT_NONCE, "little"),
            write_compact_size(self.shortids_length),
            b''.join(self.shortids),
            write_compact_size(self.prefilled_tx_length),
            b''.join([tx.to_bytes() for tx in self.prefilled_txs])
        ]
        return b''.join(parts)

    def payload_dict(self) -> dict:
        cmpctblock_dict = {
            "header": self.header.to_dict(),
            "nonce": self.nonce,
            "shortids_length": self.shortids_length,
            "shortids": {f'short_id_{x}': self.shortids[x].hex() for x in range(self.shortids_length)},
            "prefilled_txs_length": self.prefilled_tx_length,
            "prefilled_txs": {f'prefilled_tx_{y}': self.prefilled_txs[y].to_dict() for y in
                              range(self.prefilled_tx_length)}
        }
        return cmpctblock_dict


class GetBlocks(GetBlockParent):

    @property
    def command(self) -> str:
        return "getblocks"


class GetBlockTxn(Message):
    """
    The getblocktxn message is defined as a message containing a serialized BlockTransactionsRequest message and
    pchCommand == "getblocktxn".
    """

    def __init__(self, blocktxn_requestt: BlockTransactionsRequest):
        super().__init__()
        self.blocktxn_requestt = blocktxn_requestt

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        stream = get_stream(byte_stream)

        blocktxn_request = BlockTransactionsRequest.from_bytes(stream)
        return cls(blocktxn_request)

    @property
    def command(self) -> str:
        return "getblocktxn"

    def payload(self) -> bytes:
        return self.blocktxn_requestt.to_bytes()

    def payload_dict(self) -> dict:
        return self.blocktxn_requestt.to_dict()


class GetData(InvParent):

    @property
    def command(self):
        return "getdata"


class GetHeaders(GetBlockParent):
    @property
    def command(self) -> str:
        return "getheaders"


class Headers(Message):
    """
    The headers packet returns block headers in response to a getheaders packet.
    -------------------------------------------------
    |   Name    | data type |   format      | size  |
    -------------------------------------------------
    |   count   | int       | CompactSize   | var   |
    |   headers | list      | BlockHeader   | 81x   |
    -------------------------------------------------
    """

    def __init__(self, header_list: list[BlockHeader]):
        super().__init__()
        self.headers = header_list
        self.count = len(self.headers)

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        stream = get_stream(byte_stream)

        # Get count
        count = read_compact_size(stream, "headers_count")

        # Get headers
        header_list = []
        for _ in range(count):
            temp_header = BlockHeader.from_bytes(stream)
            header_list.append(temp_header)

        return cls(header_list)

    @property
    def command(self) -> str:
        return "headers"

    def payload(self) -> bytes:
        to_bytes = write_compact_size(self.count)
        for h in self.headers:
            to_bytes += h.to_bytes() + b'\x00'  # 80 byte header + 1 byte tx count set to 0
        return to_bytes

    def payload_dict(self) -> dict:
        header_dict = {}
        for x in range(self.count):
            header_dict.update({f"header_{x}": self.headers[x].to_dict()})
        to_bytes_dict = {
            "count": self.count,
            "headers": header_dict
        }
        return to_bytes_dict


class Inv(InvParent):

    @property
    def command(self):
        return "inv"


class MemPool(Message):
    """
    The mempool message sends a request to a node asking for information about transactions it has verified but which
    have not yet confirmed. The response to receiving this message is an inv message containing the transaction
    hashes for all the transactions in the node's mempool.

    No additional data is transmitted with this message.
    """

    def __init__(self):
        super().__init__()

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        stream = get_stream(byte_stream)

        # byte stream should be empty
        if len(stream) > 0:
            raise ValueError("MemPool has no payload")
        return cls()

    @property
    def command(self) -> str:
        return "mempool"

    def payload(self):
        return b''

    def payload_dict(self) -> dict:
        return {}


class MerkleBlock(Message):
    """
    -------------------------------------------------------------------------
    |   Name            |   Data type   |   byte format         |   size    |
    -------------------------------------------------------------------------
    |   Header          |   Blockheader |   to_bytes            |   80      |
    |   tx_num          |   int         |   little_endian       |   4       |
    |   hash_num        |   int         |   CompactSize         |   varint  |
    |   hashes          |   list        |   internal byte order |   32      |
    |   flag_byte_num   |   int         |   CompactSize         |   varint  |
    |   flags           |   bytes       |   little-endian       |   var     |
    -------------------------------------------------------------------------
    """

    def __init__(self, blockheader: BlockHeader, tx_num: int, hashes: list, flags: bytes):
        super().__init__()
        self.blockheader = blockheader
        self.tx_num = tx_num
        self.hash_num = len(hashes)
        self.hashes = hashes
        self.flag_num = len(flags)
        self.flags = flags

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        stream = get_stream(byte_stream)

        # header
        header = BlockHeader.from_bytes(stream)

        # tx_num
        tx_num = read_little_int(stream, BF.TXNUM, "tx_num")

        # hashes
        hash_num = read_compact_size(stream, "hash_num")
        hashes = [read_stream(stream, BF.MERKLEHASH, "merkle_hash") for _ in range(hash_num)]

        # flags
        flag_num = read_compact_size(stream, "flag_byte_count")
        flags = read_stream(stream, flag_num, "flags")

        return cls(header, tx_num, hashes, flags)

    @property
    def command(self) -> str:
        return "merkleblock"

    def payload(self) -> bytes:
        parts = [
            self.blockheader.to_bytes(),
            self.tx_num.to_bytes(BF.TXNUM, "little"),
            write_compact_size(self.hash_num),
            b''.join(self.hashes),
            write_compact_size(self.flag_num),
            self.flags
        ]
        return b''.join(parts)

    def payload_dict(self) -> dict:
        merkleblock_dict = {
            "header": self.blockheader.to_dict(),
            "tx_num": self.tx_num,
            "hash_num": self.hash_num,
            "hashes": {f"hash_{x}": self.hashes[x].hex() for x in range(self.hash_num)},
            "flag_num": self.flag_num,
            "flags": little_bytes_to_binary_string(self.flags)  # Little endian display
        }
        return merkleblock_dict


class NotFound(InvParent):

    @property
    def command(self):
        return "notfound"


class SendCompact(Message):
    """
    -------------------------------------------------------------
    |   Name    |   Data type   |   Byte format     |   size    |
    -------------------------------------------------------------
    |   Announce    |   int     |   little-endian   |   1       |
    |   version     |   int     |   little-endian   |   8       |
    -------------------------------------------------------------
    """

    def __init__(self, announce: int, version: int):
        # Error checking
        super().__init__()
        if announce not in [0, 1]:
            raise ValueError("Announce value MUST be either 0 or 1")

        self.announce = announce
        self.version = version

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        stream = get_stream(byte_stream)

        # Announce
        announce = read_little_int(stream, BF.ANNOUNCE, "announce")

        # Version
        version = read_little_int(stream, BF.CMPCT_VERSION, "version")

        return cls(announce, version)

    @property
    def command(self) -> str:
        return "sendcmpct"

    def payload(self) -> bytes:
        return self.announce.to_bytes(BF.ANNOUNCE, "little") + self.version.to_bytes(BF.CMPCT_VERSION, "little")

    def payload_dict(self) -> dict:
        return {
            "announce": self.announce,
            "version": self.version
        }


class TxMsg(Message):
    """
    Will package and send a tx
    """

    def __init__(self, tx: Transaction):
        super().__init__()
        self.tx = tx

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        # Use inherent block method
        return Transaction.from_bytes(byte_stream)

    @property
    def command(self) -> str:
        return "tx"

    def payload(self) -> bytes:
        return self.tx.to_bytes()

    def payload_dict(self) -> dict:
        return self.tx.to_dict()
