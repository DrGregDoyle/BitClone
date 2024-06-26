"""
A library for common encoding functions
"""
from hashlib import sha256

BYTE_DICT = {
    "tx": 32,
    "v_out": 4,
    "height": 16,
    "amount": 8,
    "sequence": 4,
    "byte": 1,
    "version": 4,
    "locktime": 4,
    "hash": 32,
    "target": 64,
    "bits": 4,
    "time": 4,
    "nonce": 4
}

WEIGHT_UNIT_DICT = {
    "version": 4,
    "marker": 1,
    "flag": 1,
    "input": 4,
    "output": 4,
    "witness": 1,
    "locktime": 4
}

# --- BASE58 ENCODING/DECODING --- #
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_LIST = [x for x in BASE58_ALPHABET]


def base58_check(data: int | str, checksum=True):
    # Make sure data is in hex format
    if isinstance(data, int):
        data = format(data, "0x")

    # Checksum
    if checksum:
        _checksum = sha256(data.encode()).hexdigest()[:8]
        data += _checksum

    # Convert
    buffer = ""
    data_int = int(data, 16)
    while data_int > 0:
        r = data_int % 58
        buffer = BASE58_LIST[r] + buffer
        data_int = data_int // 58

    return buffer


def decode_base58_check(encoded_data: str, checksum=True):
    total = 0
    data_range = len(encoded_data)
    for x in range(data_range):
        total += BASE58_LIST.index(encoded_data[x:x + 1]) * pow(58, data_range - x - 1)

    if checksum:
        datacheck = format(total, "0x")
        data = datacheck[:-8]
        check = datacheck[-8:]
        assert sha256(data.encode()).hexdigest()[:8] == check
    else:
        data = format(total, "0x")
    return data


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


def encode_byte_format(element: int, byte_dict_key: str, internal=False):
    """
    Use internal=True to encode the integer in internal byte order (little-endian) format.
    """
    element_chars = 2 * BYTE_DICT.get(byte_dict_key)
    formatted_element = format(element, f"0{element_chars}x")
    if internal:
        formatted_element = formatted_element[::-1]
    return formatted_element


def hash256(data: str):
    sha1_data = sha256(data.encode()).hexdigest()
    return sha256(sha1_data.encode()).hexdigest()


def bits_to_target(bits: str) -> str:
    """
    Given an 4-byte (8 character) bits string, we return the 64-character hex string.
    """
    exp = bits[:2]
    coeff = bits[2:]

    trailing_zeros = "00" * (int(exp, 16) - len(coeff) // 2)
    target_int = int(coeff + trailing_zeros, 16)
    return format(target_int, f"064x")


def target_to_bits(hex_target: str):
    """
    Given a 64-character target string we return the corresponding exponent (bit shift) as 2-char hex string (1-byte)
    """
    # Find significant byte
    byte = 0
    significant_bit_found = False
    while not significant_bit_found:
        temp_bit = hex_target[byte:byte + 2]
        if temp_bit != "00":
            significant_bit_found = True
        else:
            byte += 2

    # Get coeff
    coeff = hex_target[byte:]

    # -- Formatting -- #
    exp = format(32 - byte // 2, "02x")
    coeff = coeff[:6]
    return exp + coeff


from random import randint


def random_hex_string(length=8):
    hex_string = ""
    for x in range(length):
        num = randint(0, 15)
        hex_string += format(num, "0x")
    assert len(hex_string) == length
    return hex_string


# -- TESTING
if __name__ == "__main__":
    exp = randint(16, 32)
    coeff = randint(pow(2, 16), pow(2, 24) - 1)

    test_bits = format(exp, "02x") + format(coeff, "06x")
    print(f"BITS: {test_bits}")
    test_target = bits_to_target(test_bits)
    print(f"TARGET: {test_target}")
    print(f"len(TARGET): {len(test_target)}")
    print(f"DECODE SUCCESSFUL: {target_to_bits(test_target) == test_bits}")
