"""
A library for common encoding functions
"""
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
    "target": 4,
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


def int_to_base58(num: int) -> str:
    """
    We create the string by successively dividing by 58 and appending the corresponding symbol to our string.
    """
    # Start with empty string
    base58_string = ''

    # Return empty string if integer is negative
    if num < 0:
        return base58_string

    # Catch zero case
    if num == 0:
        base58_string = '1'

    # Create string from successive residues
    else:
        while num > 0:
            remainder = num % 58
            base58_string = BASE58_LIST[remainder] + base58_string
            num = num // 58
    return base58_string


def base58_to_int(base58_string: str) -> int:
    """
    To convert a base58 string back to an int:
        -For each character, find the numeric index in the list of alphabet characters
        -Multiply this numeric value by a corresponding power of 58
        -Sum all values
    """
    return sum([BASE58_LIST.index(base58_string[x:x + 1]) * pow(58, len(base58_string) - x - 1) for x in
                range(0, len(base58_string))])


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
