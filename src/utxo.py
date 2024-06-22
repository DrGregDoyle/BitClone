"""
A class for BitClone UTXOs
"""
import json

from src.encoder_lib import encode_compact_size, encode_byte_format


class Outpoint:
    HASH_CHARS = 64

    def __init__(self, tx_id: str, v_out: int):
        # tx_id
        self.tx_id = tx_id.zfill(self.HASH_CHARS)

        # v_out - little endian
        self.v_out = encode_byte_format(v_out, "v_out", internal=True)

    @property
    def encoded(self):
        return self.tx_id + self.v_out

    def to_json(self):
        outpoint_dict = {
            "tx_id": self.tx_id,
            "v_out": self.v_out
        }
        return json.dumps(outpoint_dict, indent=2)


class UTXO:

    def __init__(self, outpoint: Outpoint, height: int, amount: int, locking_code: str, coinbase=False):
        # outpoint
        self.outpoint = outpoint

        # height
        self.height = encode_byte_format(height, "height")

        # amount - little endian
        self.amount = encode_byte_format(amount, "amount", internal=True)

        # coinbase
        self.coinbase = "01" if coinbase else "00"

        # locking_code and locking_code_size
        self.locking_code = locking_code
        self.locking_code_size = encode_compact_size(len(self.locking_code))

    @property
    def key(self):
        return self.outpoint.encoded

    @property
    def value(self):
        return self.height + self.coinbase + self.amount + self.locking_code_size + self.locking_code

    @property
    def encoded(self):
        return self.key + self.value

    def to_json(self):
        key_dict = json.loads(self.outpoint.to_json())
        value_dict = {
            "height": self.height,
            "coinbase": self.coinbase,
            "amount": self.amount,
            "locking_code_size": self.locking_code_size,
            "locking_code": self.locking_code
        }
        utxo_dict = {
            "key": key_dict,
            "value": value_dict
        }
        return json.dumps(utxo_dict, indent=2)
