"""
Methods for writing and reading compact size data
"""
from src.core import WriteError, DATA

__all__ = ["write_compact_size", "serialize_data"]


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


def serialize_data(data: bytes) -> bytes:
    """
    Returns compact size encoding of the size of the given data plus the data
    """
    return write_compact_size(len(data)) + data
