"""
Various common methods
"""

from src.utility import *
# --- IMPORTS --- #
from src.utxo import Outpoint, UTXO

# --- METHODS --- #
BYTE_DICT = {
    "tx": 32,
    "v_out": 4,
    "height": 16,
    "amount": 8
}


def get_chars(byte_dict_key):
    return 2 * BYTE_DICT.get(byte_dict_key)


# --- ENCODE --- #

def encode_compact_size(n: int) -> str:
    """
    We return a variable length integer in hex such that the first byte indicates the length
    """
    if 0 <= n <= 0xFC:
        return format(n, f"02x")
    elif 0xFD <= n <= 0xFFFF:
        return "fd" + format(n, f"04x")
    elif 0X10000 <= n <= 0xFFFFFFFF:
        return "fe" + format(n, f"08x")
    elif 0x100000000 <= n <= 0xffffffffffffffff:
        return "ff" + format(n, f"016x")


# --- DECODE --- #

def decode_compact_size(s: str, return_length=False) -> int | tuple:
    chunk = s[:2]
    chunk_int = int(chunk, 16)
    match chunk_int:
        case 253:
            n = s[2:6]
        case 254:
            n = s[2:10]
        case 255:
            n = s[2:18]
        case _:
            n = chunk
    length = len(n)
    if return_length:
        return int(n, 16), length
    else:
        return int(n, 16)


def decode_outpoint(s: str) -> Outpoint:
    # Hex characters
    tx_chars = get_chars("tx")
    v_out_chars = get_chars("v_out")

    # tx_id
    tx_id = s[:tx_chars]

    # v_out - Little Endian
    v_out = int(s[tx_chars:tx_chars + v_out_chars][::-1], 16)

    # verify and return
    string_encoding = s[:tx_chars + v_out_chars]
    outpoint = Outpoint(tx_id, v_out)
    if outpoint.encoded != string_encoding:
        raise TypeError("Input string did not generate same Outpoint object")
    return outpoint


def decode_utxo(s: str) -> UTXO:
    # Chars
    height_chars = get_chars("height")
    amount_chars = get_chars("amount")

    # Outpoint
    outpoint = decode_outpoint(s)
    i = len(outpoint.encoded)  # Running index

    # Height
    height = int(s[i: i + height_chars], 16)
    i += height_chars

    # Coinbase
    val = int(s[i:i + 2], 16)
    coinbase = True if val > 0 else False
    i += 2

    # Amount
    amount = int(s[i: i + amount_chars][::-1], 16)  # Little Endian
    i += amount_chars

    # Locking Code
    size, increment = decode_compact_size(s, return_length=True)
    i += increment
    locking_code = s[i: i + size]

    # Verify
    string_encoding = s[:i + size]
    constructed_utxo = UTXO(outpoint, height, amount, locking_code, coinbase)
    if constructed_utxo.encoded != string_encoding:
        raise TypeError("Input string did not generate same UTXO object")
    return constructed_utxo


# --- RANDOM --- #
# TODO: Move random to tests.utility


def random_outpoint():
    tx_id = random_tx_id()
    v_out = random_v_out()
    return Outpoint(tx_id, v_out)


def random_utxo():
    outpoint = random_outpoint()
    height = random_height()
    amount = random_amount()
    locking_code = hash160(random_hash256())
    coinbase = random_bool()
    return UTXO(outpoint, height, amount, locking_code, coinbase)


# --- TESTING --- #
if __name__ == "__main__":
    outpoint1 = random_outpoint()
    outpoint2 = decode_outpoint(outpoint1.encoded)
    print(outpoint1.to_json())
    print(outpoint2.to_json())

    utxo1 = random_utxo()
    utxo2 = decode_utxo(utxo1.encoded)
    print(f"UTXO1: {utxo1.to_json()}")
    print(f"UTXO2: {utxo2.to_json()}")
