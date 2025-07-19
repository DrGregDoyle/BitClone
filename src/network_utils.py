"""
Various Utils
"""
import json
from io import BytesIO

from src.block import BlockHeader
from src.data import get_stream, read_compact_size, read_little_int, read_stream, write_compact_size, to_little_bytes, \
    Serializable
from src.tx import Transaction

__all__ = ["PrefilledTransaction", "HeaderAndShortIDs", "BlockTransactionsRequest"]


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

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


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

    def to_json(self):
        return json.dumps(self.to_dict())


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

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


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


# --- TESTING
from src.crypto import hash256
from secrets import token_bytes

if __name__ == "__main__":
    test_hash = hash256(token_bytes(4))
    leading_index = int.from_bytes(token_bytes(2), "big")
    print(f"LEADING INDEX: {leading_index}")
    test_diff_list = [write_compact_size(leading_index), write_compact_size(0), write_compact_size(0)]  # 3
    # consecutive differentially encoded indexes
    test_block_tx_request = BlockTransactionsRequest(test_hash, test_diff_list)
    print(f"TEST BLOCK TX REQUEST: {test_block_tx_request.to_json()}")
    recovered_block_tx_req = BlockTransactionsRequest.from_bytes(test_block_tx_request.to_bytes())
    print(f"RECOVERED BLOCK TX REQ: {recovered_block_tx_req.to_json()}")
