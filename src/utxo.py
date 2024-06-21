"""
A class for BitClone UTXOs
"""
import json

from src.encoder_lib import encode_compact_size


class Outpoint:
    TX_BYTES = 32
    V_OUT_BYTES = 4

    def __init__(self, tx_id: str, v_out: int):
        self.tx_id = tx_id.zfill(2 * self.TX_BYTES)
        self.v_out = format(v_out, f"0{2 * self.V_OUT_BYTES}x")[::-1]  # Little Endian

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
    HEIGHT_BYTES = 16
    AMOUNT_BYTES = 8
    TX_BYTES = 32
    V_OUT_BYTES = 4

    def __init__(self, outpoint: Outpoint, height: int, amount: int, locking_code: str, coinbase=False):
        # Decode outpoint
        self.outpoint = outpoint
        self.tx_id = outpoint.tx_id
        self.v_out = outpoint.v_out

        # Format remaining values
        self.height = format(height, f"0{2 * self.HEIGHT_BYTES}x")
        self.amount = format(amount, f"0{2 * self.AMOUNT_BYTES}x")[::-1]  # Little Endian
        self.coinbase = "01" if coinbase else "00"
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
            "locking_code": self.locking_code
        }
        utxo_dict = {
            "key": key_dict,
            "value": value_dict
        }
        return json.dumps(utxo_dict, indent=2)
