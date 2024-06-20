"""
A class for BitClone UTXOs
"""
import json
import random

from src.transaction import CompactSize, match_byte_chunk
from src.utility import random_hash256, random_integer


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


def decode_outpoint(outpoint_string: str) -> Outpoint:
    # Get chars
    tx_chars = 2 * Outpoint.TX_BYTES
    v_out_chars = 2 * Outpoint.V_OUT_BYTES

    # Get tx_id and v_out
    tx_id = outpoint_string[:tx_chars]
    current_index = tx_chars
    v_out = outpoint_string[current_index:current_index + v_out_chars]
    v_out_int = int(v_out[::-1], 16)

    # Verify
    constructed_encoding = tx_id + v_out
    constructed_outpoint = Outpoint(tx_id=tx_id, v_out=v_out_int)
    if constructed_outpoint.encoded != constructed_encoding:
        raise TypeError("Given input string did not generate same Outpoint object")
    return constructed_outpoint


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
        self.locking_code_size = CompactSize(len(self.locking_code)).encoded

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


def decode_utxo(utxo_string: str) -> UTXO:
    # Get UTXO default chars
    tx_id_chars = 2 * UTXO.TX_BYTES
    v_out_chars = 2 * UTXO.V_OUT_BYTES
    height_chars = 2 * UTXO.HEIGHT_BYTES
    amount_chars = 2 * UTXO.AMOUNT_BYTES

    # Get outpoint
    current_index = 0
    tx_id = utxo_string[:tx_id_chars]
    current_index += tx_id_chars
    v_out = utxo_string[current_index:current_index + v_out_chars]  # Little Endian
    v_out_int = int(v_out[::-1], 16)
    current_index += v_out_chars
    outpoint = Outpoint(tx_id, v_out_int)

    # Get value
    block_height = utxo_string[current_index:current_index + height_chars]
    current_index += height_chars
    block_height_int = int(block_height, 16)
    coinbase = utxo_string[current_index: current_index + 2]
    current_index += 2
    coinbase_bool = False if coinbase == "00" else True
    amount = utxo_string[current_index: current_index + amount_chars]
    current_index += amount_chars
    amount_int = int(amount[::-1], 16)

    byte_chunk = utxo_string[current_index: current_index + 2]
    current_index += 2
    increment = match_byte_chunk(byte_chunk)
    locking_code_size = utxo_string[current_index:current_index + increment] if increment else byte_chunk
    current_index += increment
    locking_code_size_int = int(locking_code_size, 16)
    locking_code = utxo_string[current_index:current_index + locking_code_size_int]
    value = block_height + coinbase + amount + locking_code_size + locking_code

    # Verify
    constructed_encoding = outpoint.encoded + value
    constructed_utxo = UTXO(outpoint=outpoint, height=block_height_int, amount=amount_int,
                            locking_code=locking_code, coinbase=coinbase_bool)
    if constructed_utxo.encoded != constructed_encoding:
        print(f"CONSTRUCTED UTXO: {constructed_utxo.to_json()}")
        raise TypeError("Given input string did not generate same UTXO object")
    return constructed_utxo


# --- TESTING --- #
if __name__ == "__main__":
    # Test Outpoint
    tx_id = random_hash256()
    v_out = random_integer(4)

    test_outpoint = Outpoint(tx_id, v_out)
    constructed_outpoint = decode_outpoint(test_outpoint.encoded)
    print(f"TEST OUTPOINT: {test_outpoint.to_json()}")
    print(f"CONSTRUCTED OUTPOINT: {constructed_outpoint.to_json()}")
    print(f"OUTPOINTS AGREE?: {test_outpoint.encoded == constructed_outpoint.encoded}")

    # Test UTXO
    block_height = random_integer(16)
    block_height_hex = format(block_height, f"0{2 * UTXO.HEIGHT_BYTES}x")
    block_height_le = block_height_hex[::-1]
    print(f"BLOCK HEIGHT HEX: {block_height_hex}")
    print(f"BLOCK HEIGHT LE: {block_height_le}")

    coinbase = random.choice([True, False])
    not_coinbase = not coinbase
    print(f"COINBASE: {coinbase}")
    amount = random_integer(8)
    amount_hex = format(amount, f"0{2 * UTXO.AMOUNT_BYTES}x")
    amount_le = amount_hex[::-1]
    print(f"AMOUNT HEX: {amount_hex}")
    print(f"AMOUNT LE: {amount_le}")
    locking_code = random_hash256()
    print(f"LOCKING CODE: {locking_code}")

    test_utxo = UTXO(outpoint=test_outpoint, height=block_height, amount=amount, locking_code=locking_code,
                     coinbase=coinbase)
    constructed_utxo = decode_utxo(test_utxo.encoded)
    print(f"TEST UTXO: {test_utxo.to_json()}")
    print(f"TEST UTXO KEY: {test_utxo.key}")
    print(f"TEST UTXO VALUE: {test_utxo.value}")
    fake_utxo = UTXO(outpoint=test_outpoint, height=block_height, amount=amount, locking_code=locking_code,
                     coinbase=not_coinbase)
    print(f"FAKE UTXO: {fake_utxo.to_json()}")
    print(f"FAKE UTXO KEY: {fake_utxo.key}")
    print(f"FAKE UTXO VALUE: {fake_utxo.value}")
    print(f"FAKE UTXO equals TEST UTXO: {test_utxo.encoded == fake_utxo.encoded}")
