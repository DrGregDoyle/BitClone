"""
All methods used for reading and writing CompactSize integers
"""
import struct
from io import BytesIO

from src.data import read_stream, get_stream

__all__ = ["read_compact_size", "write_compact_size"]


def write_compact_size(value: int) -> bytes:
    """
    Encodes an integer into a Bitcoin CompactSize (varint) byte sequence.

    Args:
        value (int): The integer value to encode.

    Returns:
        bytes: The bytes representing the CompactSize encoding of `value`.
    """
    if value < 0:
        raise ValueError("Negative values are not allowed in CompactSize encoding.")

    if value < 0xfd:
        return struct.pack("B", value)
    elif value <= 0xffff:
        return b'\xfd' + struct.pack("<H", value)
    elif value <= 0xffffffff:
        return b'\xfe' + struct.pack("<I", value)
    else:
        return b'\xff' + struct.pack("<Q", value)


def read_compact_size(byte_stream: bytes | BytesIO, log_msg: str = None) -> int:
    """
    Returns the integer value associated with the compact-size encoding at the head of the data stream
    """
    # Get BytesIO object
    stream = get_stream(byte_stream)

    # Read VarInt prefix
    prefix = read_stream(stream, 1, f"compact-size prefix: {log_msg}")
    prefix_val = prefix[0]

    if prefix_val < 0xfd:
        # Single-byte value
        return prefix_val
    elif prefix_val == 0xfd:
        # Next 2 bytes as uint16 (little-endian)
        raw = read_stream(stream, 2, f"0xfd prefix value: {log_msg}")
    elif prefix_val == 0xfe:
        # Next 4 bytes as uint32 (little-endian)
        raw = read_stream(stream, 4, f"0xfe prefix value: {log_msg}")
    else:
        # prefix_val == 0xff -> Next 8 bytes as uint64 (little-endian)
        raw = read_stream(stream, 8, f"0xff prefix value:{log_msg}")
    return int.from_bytes(raw, "little")
