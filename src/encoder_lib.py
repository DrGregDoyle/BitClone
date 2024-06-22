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
