"""
A class for BitClone UTXOs
"""
import json

from src.predicates import ByteOrder, Endian, CompactSize


class Outpoint:
    TXID_BYTES = 32
    VOUT_BYTES = 4

    def __init__(self, tx_id: str, v_out: int):
        # Assume tx_id given in natural byte order
        self.txid = ByteOrder(tx_id, reverse=False)

        # v_out | 4 bytes, little-endian
        self.v_out = Endian(v_out, byte_size=self.VOUT_BYTES)

    @property
    def bytes(self):
        return self.txid.bytes + self.v_out.bytes

    @property
    def hex(self):
        return self.bytes.hex()

    def to_json(self):
        outpoint_dict = {
            "tx_id": self.txid.hex,
            "v_out": self.v_out.hex
        }
        return json.dumps(outpoint_dict, indent=2)


class UTXO:
    HEIGHT_BYTES = 8
    AMOUNT_BYTES = 8

    def __init__(self, outpoint: Outpoint, height: int, amount: int, scriptpubkey: str, coinbase=False):
        # outpoint
        self.outpoint = outpoint

        # height | 8 bytes, little-endian
        self.height = Endian(height, byte_size=self.HEIGHT_BYTES)

        # amount | 8 bytes, little-endian
        self.amount = Endian(amount, byte_size=self.AMOUNT_BYTES)

        # coinbase
        self.coinbase = "01" if coinbase else "00"

        # locking_code and locking_code_size
        self.scriptpubkey = scriptpubkey
        self.scriptpubkey_size = CompactSize(len(self.scriptpubkey))

    @property
    def key(self):
        return self.outpoint.hex

    @property
    def value(self):
        return self.height.hex + self.coinbase + self.amount.hex + self.scriptpubkey_size.hex + self.scriptpubkey

    @property
    def bytes(self):
        return self.outpoint.bytes + bytes.fromhex(self.value)

    @property
    def hex(self):
        return self.bytes.hex()

    def to_json(self):
        key_dict = json.loads(self.outpoint.to_json())
        value_dict = {
            "height": self.height.hex,
            "coinbase": self.coinbase,
            "amount": self.amount.hex,
            "locking_code_size": self.scriptpubkey_size.hex,
            "locking_code": self.scriptpubkey
        }
        utxo_dict = {
            "key": key_dict,
            "value": value_dict
        }
        return json.dumps(utxo_dict, indent=2)
