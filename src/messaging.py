"""
Class files for messages that rely on Block or Tx
"""
from io import BytesIO

from src.block import BlockHeader, Block
from src.data import BitcoinFormats, Serializable, get_stream, read_stream, read_compact_size, write_compact_size, \
    read_little_int, little_bytes_to_binary_string, to_little_bytes
from src.tx import Transaction

__all__ = ["HeaderMessage", "PrefilledTransaction", "BlockTransactions", "HeaderAndShortIDs",
           "BlockTransactionsRequest", "MerkleBlock"]

# --- ALIASING
MB = BitcoinFormats.MagicBytes
CB = BitcoinFormats.CompactBlock


# --- TRANSACTIONS --- #


# --- BLOCKS --- #


# --- COMPACTBLOCKS --- #
class PrefilledTransaction(Serializable):
    """
    -------------------------------------------------------------
    |   Name    |   Data type   |   byte format |   byte size   |
    -------------------------------------------------------------
    |   Index   |   int         |   CompactSize |   varInt      |
    |   Tx      |   Transaction |   tx.to_bytes |   var         |
    -------------------------------------------------------------
    """

    def __init__(self, index: int, tx: Transaction):
        self.index = index
        self.tx = tx

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        stream = get_stream(byte_stream)

        # index
        index = read_compact_size(stream, "prefilled_tx_index")

        # tx
        tx = Transaction.from_bytes(stream)

        return cls(index, tx)

    def to_bytes(self) -> bytes:
        return write_compact_size(self.index) + self.tx.to_bytes()

    @property
    def command(self) -> str:
        return ""

    def differentially_encode_index(self, previous_index: int):
        self.index = abs(self.index - previous_index - 1)

    def to_dict(self):
        prefilled_tx_dict = {
            "index": self.index,
            "tx": self.tx.to_dict()
        }
        return prefilled_tx_dict


class BlockTransactions(Serializable):
    """
    Added in protocol version 70014 as described by BIP152.
    ---------------------------------------------------------------------
    |   Name        |	Data Type   | Byte Format           |   Size    |
    ---------------------------------------------------------------------
    |   block_hash  | bytes         |   natural_byte_order  |   32      |
    |   tx_num      |   int         |   CompactSize         |   varint  |
    |   txs         |   list        |   tx.to_bytes()       |   var     |
    ---------------------------------------------------------------------
    """
    BLOCKHASH_BYTES = 32

    def __init__(self, block_hash: bytes, txs: list[Transaction]):
        self.block_hash = block_hash
        self.txs = txs
        self.tx_num = len(txs)

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        stream = get_stream(byte_stream)

        # Get hash
        block_hash = read_stream(stream, cls.BLOCKHASH_BYTES, "block_hash")

        # Get txs
        tx_num = read_compact_size(stream, "BlockTransactions.tx_num")
        txs = [Transaction.from_bytes(stream) for _ in range(tx_num)]

        return cls(block_hash, txs)

    def to_bytes(self) -> bytes:
        tx_bytes = b''.join([tx.to_bytes() for tx in self.txs])
        return self.block_hash + write_compact_size(self.tx_num) + tx_bytes

    def to_dict(self) -> dict:
        blocktx_dict = {
            "block_hash": self.block_hash[::-1].hex(),  # Reverse for display
            "tx_num": self.tx_num,
            "txs": {f"tx_{x}": self.txs[x].to_dict() for x in range(self.tx_num)}
        }
        return blocktx_dict


class BlockMessage(Serializable):
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

    def to_bytes(self) -> bytes:
        return self.block.to_bytes()

    def to_dict(self) -> dict:
        return self.block.to_dict()


class TxMessage(Serializable):
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

    def to_bytes(self) -> bytes:
        return self.tx.to_bytes()

    def to_dict(self) -> dict:
        return self.tx.to_dict()


class HeaderMessage(Serializable):
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

    def to_bytes(self) -> bytes:
        to_bytes = write_compact_size(self.count)
        for h in self.headers:
            to_bytes += h.to_bytes() + b'\x00'  # 80 byte header + 1 byte tx count set to 0
        return to_bytes

    def to_dict(self) -> dict:
        header_dict = {}
        for x in range(self.count):
            header_dict.update({f"header_{x}": self.headers[x].to_dict()})
        to_bytes_dict = {
            "count": self.count,
            "headers": header_dict
        }
        return to_bytes_dict


class BlockTxn(Serializable):

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

    def to_bytes(self) -> bytes:
        return self.block_tx.to_bytes()

    def to_dict(self) -> dict:
        return {"block_txn": self.block_tx.to_dict()}


class MerkleBlock(Serializable):
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

    def __init__(self, header: BlockHeader, tx_num: int, hashes: list, flags: bytes):
        super().__init__()
        self.header = header
        self.tx_num = tx_num
        self.hash_num = len(hashes)
        self.hashes = hashes
        self.flag_num = len(flags)
        self.flags = flags

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MB.MAINNET):
        stream = get_stream(byte_stream)

        # header
        header = BlockHeader.from_bytes(stream)

        # tx_num
        tx_num = read_little_int(stream, CB.TX_NUM, "tx_num")

        # hashes
        hash_num = read_compact_size(stream, "hash_num")
        hashes = [read_stream(stream, CB.MERKLE_HASH, "merkle_hash") for _ in range(hash_num)]

        # flags
        flag_num = read_compact_size(stream, "flag_byte_count")
        flags = read_stream(stream, flag_num, "flags")

        return cls(header, tx_num, hashes, flags)

    @property
    def command(self) -> str:
        return "merkleblock"

    def to_bytes(self) -> bytes:
        parts = [
            self.header.to_bytes(),
            self.tx_num.to_bytes(CB.TX_NUM, "little"),
            write_compact_size(self.hash_num),
            b''.join(self.hashes),
            write_compact_size(self.flag_num),
            self.flags
        ]
        return b''.join(parts)

    def to_dict(self) -> dict:
        merkleblock_dict = {
            "header": self.header.to_dict(),
            "tx_num": self.tx_num,
            "hash_num": self.hash_num,
            "hashes": {f"hash_{x}": self.hashes[x].hex() for x in range(self.hash_num)},
            "flag_num": self.flag_num,
            "flags": little_bytes_to_binary_string(self.flags)  # Little endian display
        }
        return merkleblock_dict


class GetBlockTxn(Serializable):
    """
    The getblocktxn message is defined as a message containing a serialized BlockTransactionsRequest message and
    pchCommand == "getblocktxn".
    """

    def __init__(self, blocktxn: BlockTransactions):
        super().__init__()
        self.blocktxn = blocktxn

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MB.MAINNET):
        stream = get_stream(byte_stream)

        blocktxn = BlockTransactions.from_bytes(stream)
        return cls(blocktxn)

    @property
    def command(self) -> str:
        return "getblocktxn"

    def to_bytes(self) -> bytes:
        return self.blocktxn.to_bytes()

    def to_dict(self) -> dict:
        return self.blocktxn.to_dict()


class HeaderAndShortIDs(Serializable):
    """
    ---------------------------------------------------------------------------------
    |   Name                |   Data type       |   byte format     |   byte size   |
    ---------------------------------------------------------------------------------
    |   Header              |   Block header    |   header.to_bytes |   80          |
    |   Nonce               |   int             |   little-endian   |   8           |
    |   shorts_ids_length   |   int             |   CompactSize     |   varint      |
    |   shortids            |   list            |   little-endian   |   8 * length  |
    |   prefilled_tx_length |   int             |   CompactSize     |   varint      |
    |   prefilled_tx        |   list            |   tx.to_bytes     |   var         |
    ---------------------------------------------------------------------------------
    """
    NONCE_BYTES = 8
    SHORTIDS_BYTES = 6

    def __init__(self, header: BlockHeader, nonce: int, short_ids: list, prefilled_txs: list[PrefilledTransaction]):
        self.header = header
        self.nonce = nonce
        self.shortids = short_ids
        self.shortids_length = len(short_ids)
        self.prefilledtxn = prefilled_txs
        self.prefilledtxn_length = len(prefilled_txs)

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        stream = get_stream(byte_stream)

        # Get data
        header = BlockHeader.from_bytes(stream)
        nonce = read_little_int(stream, cls.NONCE_BYTES, "nonce")
        shortids_length = read_compact_size(stream, "shortids_length")
        shortids = []
        for _ in range(shortids_length):
            shortids.append(read_stream(stream, cls.SHORTIDS_BYTES, "short_ids"))
        prefilledtxn_length = read_compact_size(stream, "prefilledtxn_length")
        prefilledtxn = []
        for _ in range(prefilledtxn_length):
            prefilledtxn.append(PrefilledTransaction.from_bytes(stream))

        return cls(header, nonce, shortids, prefilledtxn)

    def to_bytes(self):

        return (self.header.to_bytes() + to_little_bytes(self.nonce, self.NONCE_BYTES)
                + write_compact_size(self.shortids_length) + b''.join(self.shortids)
                + write_compact_size(self.prefilledtxn_length) + b''.join([t.to_bytes() for t in self.prefilledtxn]))

    def to_dict(self):
        short_ids_dict = {}
        for x in range(self.shortids_length):
            temp_shortid = self.shortids[x]
            short_ids_dict.update({
                f"short_id_{x}": temp_shortid.hex()
            })

        header_and_short_ids_dict = {
            "header": self.header.to_dict(),
            "nonce": self.nonce,
            "shortids_length": self.shortids_length,
            "shortids": short_ids_dict,  # {f"id_{x}": self.shortids[x].hex() for x in range(self.shortids_length)},
            "prefilledtxn_length": self.prefilledtxn_length,
            "prefilledtxn": {f"prefilled_txn_{x}": self.prefilledtxn[x].to_dict() for x in
                             range(self.prefilledtxn_length)}
        }
        return header_and_short_ids_dict


class BlockTransactionsRequest(Serializable):
    """
    ---------------------------------------------------------------------------------
    |   Name            |   Data type   |   byte format             |   byte size   |
    ---------------------------------------------------------------------------------
    |   block_hash      |   bytes       |   natural_byte_order      |   32          |
    |   indexes_length  |   int         |   CompactSize             |   varint      |
    |   indexes         |   list        |   Differentially encoded  |   var         |
    ---------------------------------------------------------------------------------
    """
    BLOCKHASH_BYTES = 32

    def __init__(self, block_hash: bytes, indexes: list):
        """
        We assume that the indexes list is already differentially encoded
        """
        self.block_hash = block_hash
        self.indexes = indexes
        self.indexes_length = len(indexes)

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        # Get stream
        stream = get_stream(byte_stream)

        # Get block_hash
        block_hash = read_stream(stream, cls.BLOCKHASH_BYTES, "block_hash")

        # Get indexes
        indexes_length = read_compact_size(stream, "indexes_length")
        indexes = []
        for _ in range(indexes_length):
            indexes.append(write_compact_size(read_compact_size(stream, "differentially encoded index")))

        return cls(block_hash, indexes)

    def to_bytes(self):
        return self.block_hash + write_compact_size(self.indexes_length) + b''.join(self.indexes)

    def to_dict(self):
        index_dict = {}
        diff_encode_dict = {}
        current_index = read_compact_size(get_stream(self.indexes[0]), "Compact Size")

        for x in range(self.indexes_length):
            # First index case
            if x == 0:
                index_dict.update({
                    "index_0": current_index
                })
                diff_encode_dict.update({
                    "differentially_encoded_index_0": current_index
                })
            # Remaining elements in list
            else:
                temp_index = read_compact_size(get_stream(self.indexes[x]), "Differentially encoded int")
                diff_encode_dict.update({
                    f"differentially_encoded_index_{x}": temp_index
                })
                current_index = temp_index + 1 + current_index
                index_dict.update({
                    f"index_{x}": current_index
                })

        block_tx_req_dict = {
            "block_hash": self.block_hash[::-1].hex(),  # reverse byte order for display
            "index_count": self.indexes_length,
            "index list": index_dict,
            "differentially encoded indexes": diff_encode_dict
        }
        return block_tx_req_dict


class CompactBlock(Serializable):
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
    NONCE_BYTES = SHORTIDS_BYTES = 8

    def __init__(self, header: BlockHeader, nonce: int, shortids: list[bytes],
                 prefilled_txs: list[PrefilledTransaction]):
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
        nonce = read_little_int(stream, cls.NONCE_BYTES, "nonce")

        # shortids
        shortids_length = read_compact_size(stream, "shortids_length")
        shortids = [read_stream(stream, cls.SHORTIDS_BYTES, "shortids") for _ in range(shortids_length)]

        # prefilled_txs
        prefilled_tx_length = read_compact_size(stream, "prefilled_tx_length")
        prefilled_txs = [PrefilledTransaction.from_bytes(stream) for _ in range(prefilled_tx_length)]

        return cls(header, nonce, shortids, prefilled_txs)

    def to_bytes(self) -> bytes:
        parts = [
            self.header.to_bytes(),
            to_little_bytes(self.nonce, self.NONCE_BYTES),
            write_compact_size(self.shortids_length),
            b''.join(self.shortids),
            write_compact_size(self.prefilled_tx_length),
            b''.join([tx.to_bytes() for tx in self.prefilled_txs])
        ]
        return b''.join(parts)

    def to_dict(self) -> dict:
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
