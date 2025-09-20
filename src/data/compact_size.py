"""
Methods for writing and reading compact size data
"""
from src.core import get_stream, read_little_int, SERIALIZED, ReadError, WriteError, DATA

__all__ = ["read_compact_size", "write_compact_size"]


def read_compact_size(byte_stream: SERIALIZED) -> int:
    stream = get_stream(byte_stream)

    # Prefix
    prefix = read_little_int(stream, 1, "Compact Size Prefix")

    # One byte compact size number
    if prefix <= 0xfc:
        return prefix

    # Match prefix otherwise
    match prefix:
        case 0xfd:
            return read_little_int(stream, 2, "Compact Size: Oxfd")
        case 0xfe:
            return read_little_int(stream, 4, "Compact Size: 0xfe")
        case 0xff:
            return read_little_int(stream, 8, "Compact Size: 0xff")
        case _:
            raise ReadError(f"Incorrect prefix {hex(prefix)} for CompactSize encoding")


def write_compact_size(num: int) -> bytes:
    """
    Given an integer we return its CompactSize encoding
    """
    # --- Validation --- #
    if num < 0 or num > DATA.MAX_COMPACTSIZE:
        raise WriteError("Given number out of bounds for CompactSize encoding")

    if num <= 0xfc:  # One byte
        return num.to_bytes(1, "little")
    elif num <= 0xffff:  # Two bytes
        return b'\xfd' + num.to_bytes(2, "little")
    elif num <= 0xffffffff:  # Four bytes
        return b'\xfe' + num.to_bytes(4, "little")
    else:  # Eight bytes
        return b'\xff' + num.to_bytes(8, "little")
