"""
Various Utils
"""
import json
from io import BytesIO

from src.data.byte_stream import get_stream, read_compact_size
from src.data.data_handling import write_compact_size
from src.data.magic_bytes import MAINNET
from src.tx import Transaction


class PrefilledTransaction:

    def __init__(self, index: int, tx: Transaction):
        self.index = index
        self.tx = tx

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MAINNET):
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

