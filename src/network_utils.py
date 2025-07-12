"""
Various Utils
"""
import json
from io import BytesIO

from src.block import BlockHeader
from src.data.byte_stream import get_stream, read_compact_size, read_little_int
from src.data.data_handling import write_compact_size, to_little_bytes
from src.tx import Transaction

__all__ = ["PrefilledTransaction", "HeaderAndShortIDs"]


class PrefilledTransaction:

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


class HeaderAndShortIDs:
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
            shortids.append(read_little_int(stream, cls.SHORTIDS_BYTES, "shortids"))
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
        header_and_short_ids_dict = {
            "header": self.header.to_dict(),
            "nonce": self.nonce,
            "shortids_length": self.shortids_length,
            "shortids": {f"id_{x}": self.shortids[x].hex() for x in range(self.shortids_length)},
            "prefilledtxn_length": self.prefilledtxn_length,
            "prefilledtxn": {f"prefilled_txn_{x}": self.prefilledtxn[x].to_dict() for x in
                             range(self.prefilledtxn_length)}
        }
        return header_and_short_ids_dict

    def to_json(self):
        return json.dumps(self.to_dict())


# --- TESTING
if __name__ == "__main__":
    pass
