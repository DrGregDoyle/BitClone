"""
A class for BitClone UTXOs
"""
import json

from src.encoder_lib import EncodedNum


class Outpoint:
    HASH_CHARS = 64
    VOUT_BYTES = 4  # Little Endian

    def __init__(self, tx_id: str, v_out: int):
        # tx_id
        self.tx_id = tx_id.zfill(self.HASH_CHARS)  # TODO: Verify if zfill is necessary

        # v_out - little endian
        self.v_out = EncodedNum(v_out, byte_size=self.VOUT_BYTES, encoding="little").display

    @property  # TODO: Turn encoded into bytestream and display into hex strings
    def encoded(self):
        return self.tx_id + self.v_out

    def to_json(self):
        outpoint_dict = {
            "tx_id": self.tx_id,
            "v_out": self.v_out
        }
        return json.dumps(outpoint_dict, indent=2)


class UTXO:
    HEIGHT_BYTES = 8
    AMOUNT_BYTES = 8

    def __init__(self, outpoint: Outpoint, height: int, amount: int, locking_code: str, coinbase=False):
        # outpoint
        self.outpoint = outpoint

        # height
        self.height = EncodedNum(height, byte_size=self.HEIGHT_BYTES).display

        # amount - little endian
        self.amount = EncodedNum(amount, byte_size=self.AMOUNT_BYTES, encoding="little").display

        # coinbase
        self.coinbase = "01" if coinbase else "00"

        # locking_code and locking_code_size
        self.locking_code = locking_code
        self.locking_code_size = EncodedNum(len(self.locking_code), encoding="compact").display

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
