"""
Data Messages for P2P networking
"""
from src.blockchain.block import Block, BlockHeader
from src.core import SERIALIZED, get_bytes, get_stream, read_compact_size, NetworkDataError, read_little_int, \
    read_stream
from src.data import write_compact_size
from src.network.message import Message, EmptyMessage
from src.network.network_data import InvVector, BlockTransactions, BlockTransactionsRequest, HeaderAndShortIDs
from src.tx import Transaction

__all__ = ["BlockMessage", "CmpctBlock", "GetBlocks", "GetData", "GetHeaders", "Headers", "Inv", "MemPool", "NotFound",
           "TxMessage", "BlockTxn", "GetBlockTxn"]


class BlockMessage(Message):
    """
    We transmit a Block in a message
    =================================================================================
    |   Name        | data type         | format                            | size  |
    =================================================================================
    |   block       |   Block           |   Block.to_bytes()                |   var |
    =================================================================================
    """
    COMMAND = "block"

    def __init__(self, block: Block):
        super().__init__()  # For magic bytes
        self.block = block

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        block_bytes = get_bytes(byte_stream)
        return cls(Block.from_bytes(block_bytes))

    def to_payload(self):
        return self.block.to_bytes()

    def payload_dict(self, formatted: bool = True) -> dict:
        return {"block": self.block.to_dict(formatted)}


class TxMessage(Message):
    """
    We transmit a Block in a message
    =====================================================================
    |   Name    |   data type       |   format                  | size  |
    =====================================================================
    |   tx      |   Transaction     |   Transaction.to_bytes()  |   var |
    =====================================================================
    """
    COMMAND = "tx"

    def __init__(self, tx: Transaction):
        super().__init__()  # For magic bytes
        self.tx = tx

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        tx_bytes = get_bytes(byte_stream)
        return cls(Transaction.from_bytes(tx_bytes))

    def to_payload(self):
        return self.tx.to_bytes()

    def payload_dict(self, formatted: bool = True) -> dict:
        return {"tx": self.tx.to_dict(formatted)}


# === GETBLOCKS TYPE === #

class GetBlockParent(Message):
    """
    The parent class for GetBlocks and GetHeaders.
    =========================================================================
    |   Name        |   data type   |   format                  |   size    |
    =========================================================================
    |   version         |   int         |   little-endian       |   4       |
    |   hash_count      |   int         |   CompactSize         |   var     |
    |   locator_hashes  |   list[bytes] |   natural byte order  |   32      |
    |   hash_stop       |   bytes       |   natural byte order  |   32      |
    =========================================================================
    *When hash_stop is set to 0, we return the max number of blocks.
    GetBlocks can include max 500 hashes. GetHeaders can include max 2000 headers
    """
    MAX = None  # To be overridden by subclasses

    def __init__(self, version: int, locator_hashes: list[bytes], hash_stop: bytes = None):
        super().__init__()
        self.version = version
        self.locator_hashes = locator_hashes
        self.hash_stop = hash_stop if hash_stop else bytes(32)

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # version
        version = read_little_int(stream, 4)

        # locator hashes
        hash_count = read_compact_size(stream)
        locator_hashes = [read_stream(stream, 32) for _ in range(hash_count)]

        # hash stop
        hash_stop = read_stream(stream, 32)

        return cls(version, locator_hashes, hash_stop)

    def to_payload(self) -> bytes:
        parts = [
            self.version.to_bytes(4, "little"),
            write_compact_size(len(self.locator_hashes)), b''.join(self.locator_hashes), self.hash_stop
        ]
        return b''.join(parts)

    def payload_dict(self, formatted: bool = True) -> dict:
        hash_count = len(self.locator_hashes)
        locator_dict = {
            f"locator_hash_{x}": self.locator_hashes[x].hex() for x in range(hash_count)
        }
        return {
            "version": self.version.to_bytes(4, "little").hex() if formatted else self.version,
            "hash_count": write_compact_size(hash_count).hex() if formatted else hash_count,
            "locator_hashes": locator_dict,
            "hash_stop": self.hash_stop.hex()
        }


class GetBlocks(GetBlockParent):
    """Return an inv packet containing the list of blocks starting right after the last known hash in the block locator
        object, up to hash_stop or 500 blocks, whichever comes first
    """
    COMMAND = "getblocks"
    MAX = 500


class GetHeaders(GetBlockParent):
    COMMAND = "getheaders"
    MAX = 2000


# === HEADERS === #
class Headers(Message):
    """Send BlockHeaders in response to a GetHeaders message
    =================================================================================
    |   Name        |   data type           |   format                  |   size    |
    =================================================================================
    |   count       |   int                 |   CompactSize             |   var     |
    |   headers     |   list[BlockHeader]   |   BlockHeader.to_bytes()  |   81      |
    =================================================================================
    * We always include a 00 at the end of the BlockHeader to indicate the tx_count (which is always 0 for a header)
    """
    COMMAND = "headers"

    def __init__(self, headers: list[BlockHeader]):
        super().__init__()
        self.headers = headers

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # header count
        count = read_compact_size(stream)

        # headers
        headers = []
        for _ in range(count):
            temp_header = BlockHeader.from_bytes(stream)
            tx_count = read_little_int(stream, 1)
            # Validate
            if tx_count != 0:
                raise NetworkDataError("Headers Payload must contain 0 tx_count value appended to each header")
            headers.append(temp_header)

        return cls(headers)

    def to_payload(self) -> bytes:
        header_parts = [h.to_bytes() + b'\x00' for h in self.headers]
        return write_compact_size(len(self.headers)) + b''.join(header_parts)

    def payload_dict(self, formatted: bool = True) -> dict:
        count = len(self.headers)
        return {
            "count": write_compact_size(count).hex() if formatted else count,
            "headers": {
                f"header_{x}": self.headers[x].to_dict(formatted) for x in range(count)
            }
        }


# === BLOCK TRANSACTIONS === #
class BlockTxn(Message):
    """
    Contains a serialized BlockTransactions message
    *Only supported by protocol version >=70014
    """
    COMMAND = "blocktxn"

    def __init__(self, txn: BlockTransactions):
        super().__init__()
        self.txn = txn

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)
        txn = BlockTransactions.from_bytes(stream)
        return cls(txn)

    def to_payload(self) -> bytes:
        return self.txn.to_bytes()

    def payload_dict(self, formatted: bool = True) -> dict:
        return self.txn.to_dict(formatted)


class GetBlockTxn(Message):
    """Contains a serialized GetBlockTxn message
    """
    COMMAND = "getblocktxn"

    def __init__(self, block_txn_req: BlockTransactionsRequest):
        super().__init__()
        self.block_txn_req = block_txn_req

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        block_txn_req = BlockTransactionsRequest.from_bytes(stream)
        return cls(block_txn_req)

    def to_payload(self) -> bytes:
        return self.block_txn_req.to_bytes()

    def payload_dict(self, formatted: bool = True) -> dict:
        return self.block_txn_req.to_dict(formatted)


# === MERKLE BLOCK === #
class MerkleBlock(Message):
    """The reply to a getdata message with type MSG_MERKLEBLOCK
    =========================================================================
    |   Name            | datatype      | format                | size      |
    =========================================================================
    |   header          |   Blockheader |   to_bytes            |   80      |
    |   tx_num          |   int         |   little_endian       |   4       |
    |   hash_num        |   int         |   CompactSize         |   varint  |
    |   hashes          |   list        |   internal byte order |   32      |
    |   flag_bytes      |   int         |   CompactSize         |   varint  |
    |   flags           |   bytes       |   little-endian       |   var     |
    =========================================================================
    * The flags are decoded into bits, least-sig bit first
    """
    COMMAND = "merkleblock"

    def __init__(self, header: BlockHeader, tx_num: int, hashes: list[bytes], flags: bytes):
        super().__init__()
        self.header = header
        self.tx_num = tx_num
        self.hashes = hashes
        self.flags = flags

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # header
        header = BlockHeader.from_bytes(stream)

        # tx_num
        tx_num = read_little_int(stream, 4)

        # hashes
        hash_num = read_compact_size(stream)
        hashes = [read_stream(stream, 32) for _ in range(hash_num)]

        # flags
        flag_bytes = read_compact_size(stream)
        flags = read_stream(stream, flag_bytes)

        return cls(header, tx_num, hashes, flags)

    def to_payload(self) -> bytes:
        hash_num = len(self.hashes)
        flag_bytes = len(self.flags)
        parts = [
            self.tx_num.to_bytes(4, "little"),
            write_compact_size(hash_num),
            b''.join(self.hashes),
            write_compact_size(flag_bytes),
            self.flags
        ]
        return b''.join(parts)

    def payload_dict(self, formatted: bool = True) -> dict:
        hash_num = len(self.hashes)
        flag_bytes = len(self.flags)
        bit_string = ''.join(f'{b:08b}' for b in self.flags)
        formatted_bit_string = ''.join(f'{b:08b}'[::-1] for b in self.flags)
        hash_dict = {
            f"hash_{x}": self.hashes[x].hex() for x in range(hash_num)
        }

        return {
            "block_header": self.header.to_dict(formatted),
            "tx_count": self.tx_num.to_bytes(4, "little").hex() if formatted else self.tx_num,
            "hash_count": write_compact_size(hash_num).hex() if formatted else hash_num,
            "hashes": hash_dict,
            "flag_byte_count": write_compact_size(flag_bytes).hex() if formatted else flag_bytes,
            "flags": formatted_bit_string if formatted else bit_string
        }


# === CMPCT BLOCK === #
class CmpctBlock(Message):
    """
    A reply to a GetData message with type MSG_CMPCT_BLOCK
        -Containes a serialized HeaderAndShortIDs
    """
    COMMAND = "cmpctblock"

    def __init__(self, header_and_shortids: HeaderAndShortIDs):
        super().__init__()
        self.hashids = header_and_shortids

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)
        header_and_shortids = HeaderAndShortIDs.from_bytes(stream)
        return cls(header_and_shortids)

    def to_payload(self) -> bytes:
        return self.hashids.to_bytes()

    def payload_dict(self, formatted: bool = True) -> dict:
        return self.hashids.to_dict(formatted)


class SendCmpct(Message):
    """
    The Send Compact Block announcement message
    =================================================================
    |   Name        |   Datatype    |   Format          |   Size    |
    =================================================================
    |   announce    |   bool        |   bytes           |   1       |
    |   version     |   int         |   little-endian   |   8       |
    =================================================================
    """

    def __init__(self, announce: bool, version: int):
        super().__init__()
        self.announce = announce
        self.version = version

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # announce
        boolint = read_little_int(stream, 1)

        # version
        version = read_little_int(stream, 8)
        return cls(bool(boolint), version)

    def to_payload(self) -> bytes:
        boolint = int(self.announce)
        return boolint.to_bytes(1, "little") + self.version.to_bytes(8, "little")

    def payload_dict(self, formatted: bool = True) -> dict:
        return {
            "announce": int(self.announce).to_bytes(1, "little").hex() if formatted else self.announce,
            "version": self.version.to_bytes(8, "little").hex() if formatted else self.version
        }


# === INV TYPE === #

class InvParent(Message):
    """
    Sends an Inventory message
    =========================================================================
    |   Name        |   data type   |   format                  |   size    |
    =========================================================================
    |   count       |   int         |   CompactSize             |   var     |
    |   items       |   InvVector   |   InvVector.to_bytes()    |   var     |
    =========================================================================
    """

    MAX_ENTRIES = 50000

    def __init__(self, items: list[InvVector]):
        # Validation
        if len(items) > self.MAX_ENTRIES:
            raise NetworkDataError("Inventory list exceeds maximum entries")
        super().__init__()
        self.items = items

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # count
        count = read_compact_size(stream)

        # items
        items = [InvVector.from_bytes(stream) for _ in range(count)]

        return cls(items)

    def to_payload(self) -> bytes:
        return write_compact_size(len(self.items)) + b''.join([i.to_bytes() for i in self.items])

    def payload_dict(self, formatted: bool = True) -> dict:
        count = len(self.items)
        inv_dict = {
            f"{x}": self.items[x].to_dict(formatted) for x in range(count)
        }
        return {
            "count": write_compact_size(count).hex() if formatted else count,
            "inventory": inv_dict
        }


class Inv(InvParent):
    COMMAND = "inv"


class NotFound(InvParent):
    COMMAND = "notfound"


class GetData(InvParent):
    COMMAND = "getdata"


# === EMPTY MESSAGES === #
class MemPool(EmptyMessage):
    COMMAND = "mempool"


# --- TESTING --- #
if __name__ == "__main__":
    sep = "===" * 40

    # --- BlockMessage --- #

    known_block_bytes = bytes.fromhex(
        "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000")
    known_block = Block.from_bytes(known_block_bytes)
    test_block_msg = BlockMessage(known_block)

    # --- TX MESSAGE --- #
    known_tx_bytes = bytes.fromhex(
        "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000")
    known_tx = Transaction.from_bytes(known_tx_bytes)
    test_tx_msg = TxMessage(known_tx)

    # --- INV MESSAGE --- #
    known_inv_bytes = bytes.fromhex(
        "0201000000de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a0100000091d36d997037e08018262978766f24b8a055aaf1d872e94ae85e9817b2c68dc7")
    test_inv_mesg = Inv.from_payload(known_inv_bytes)

    # --- GETBLOCK MESSAGE --- #
    known_getblock_bytes = bytes.fromhex(
        "7111010002d39f608a7775b537729884d4e6633bb2105e55a16a14d31b00000000000000005c3e6403d40837110a2e8afb602b1c01714bda7ce23bea0a00000000000000000000000000000000000000000000000000000000000000000000000000000000")
    test_getblock = GetBlocks.from_payload(known_getblock_bytes)

    # --- HEADERS MESSAGE --- #
    known_headers_bytes = bytes.fromhex(
        "0102000000b6ff0b1b1680a2862a30ca44d346d9e8910d334beb48ca0c00000000000000009d10aa52ee949386ca9385695f04ede270dda20810decd12bc9b048aaab3147124d95a5430c31b18fe9f086400")
    test_headers = Headers.from_payload(known_headers_bytes)

    # --- BLOCKTRANSACTIONS MESSAGE --- #
    # --- BlockTransactions --- #
    # display hash
    known_block_hash = bytes.fromhex("000000000000b0b8b4e8105d62300d63c8ec1a1df0af1c2cdbd943b156a8cd79")[::-1]
    known_tx_bytes1 = bytes.fromhex(
        "010000000199db128ad1e9247b8f9182ff57c45949230ff2e9c3f1dd26e6f1c9799ae563c7000000008b48304502203153950a39db89129739d79655e18e844910fc390df3e757444608d68ab7c802022100d679e030889cb2467451c172f8d63c58e85be633f1acdbf85fab87ed95c9eee9014104d0ed1abeba4ecb8e1cdeb2531e0b9adda7541482b60c86e637af94ec82c3aefa777ea9ea50d5242504d19fa4a0500c072db5e5addee09d6808b57d75dd1dd48bffffffff02008eb462000000001976a9143f6a97f34f8c5f6cc697d9650498f3f27060489a88acc0d8a700000000001976a9143478fffab9d7e8d5ec19199e46dcfcf6c6ecb2cf88ac00000000")
    known_tx_bytes2 = bytes.fromhex(
        "0100000001d38c4935a387c0cd0658bddaf9553cdf743221e248cbc02e360ace70fdee721b010000008b4830450221009fce94f4489c0f412d181780a5131cf2bd8d926c38878bb520047e4498e85292022078cca9f887ff4c143800eca06c3faa970b65e14013abe1bb45d548e9c6e3825a014104d987807bdac7bc5935067fa4704e87b6a45c3451f4a0b939a513d3cddc1177a729a5d62195abb94b0c532f616b5e5f0f4b09c15008f9470bf5a8c91e01d5995fffffffff02c0d8a700000000001976a914795c679389d97af7ee450f1237bd8944d03b4bff88ac80dc6461000000001976a914526a1a0926fb3d9df1f7ab101075553106f8d84e88ac00000000")
    tx1 = Transaction.from_bytes(known_tx_bytes1)
    tx2 = Transaction.from_bytes(known_tx_bytes2)

    test_block_tx = BlockTransactions(known_block_hash, [tx1, tx2])
    test_block_tx_msg = BlockTxn(test_block_tx)

    # --- MERKLEBLOCK --- #
    known_merkleblock_payload = bytes.fromhex(
        "0100000082bb869cf3a793432a66e826e05a6fc37469f8efb7421dc880670100000000007f16c5962e8bd963659c793ce370d95f093bc7e367117b3c30c1f8fdd0d9728776381b4d4c86041b554b852907000000043612262624047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b6541ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d06820d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf011d")
    test_merklblock = MerkleBlock.from_payload(known_merkleblock_payload)

    # --- SENDCMPCT --- #
    test_send_compact = SendCmpct(True, 2)
    test_send_compact2 = SendCmpct(False, 1)

    # --- LOGGING --- #
    print(f"=== DATA MESSAGE TESTING ===")
    # print(sep)
    # print(f"BLOCK MESSAGE: {test_block_msg.to_json()}")
    # print(sep)
    # print(f"TX MESSAGE: {test_tx_msg.to_json(False)}")
    # print(sep)
    # print(f"INV MESSAGE: {test_inv_mesg.to_json(False)}")
    # print(sep)
    # print(f"GETBLOCKS: {test_getblock.to_json(False)}")
    # print(sep)
    # print(f"HEADERS: {test_headers.to_json()}")
    # print(sep)
    # print(f"BLOCK TRANSACTIONS: {test_block_tx_msg.to_json(False)}")
    # print(sep)
    # print(f"MERKLE BLOCK: {test_merklblock.to_json()}")
    print(sep)
    print(f"SEND COMPACT 1: {test_send_compact.to_json()}")
    print(f"SEND COMPACT 2: {test_send_compact2.to_json()}")
    print(sep)
