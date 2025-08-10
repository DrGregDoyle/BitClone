"""
Helper functions for the Serialization.from_bytes() method(s)
"""
from io import BytesIO

__all__ = ["get_stream", "read_stream", "read_little_int", "read_big_int", "read_compact_size"]


def get_stream(byte_stream: bytes | BytesIO):
    if not isinstance(byte_stream, (bytes, BytesIO)):
        raise ValueError(f"Expected byte data stream, received {type(byte_stream)}")

    stream = BytesIO(byte_stream) if isinstance(byte_stream, bytes) else byte_stream
    return stream


def read_stream(stream: BytesIO, length: int, data_type: str):
    data = stream.read(length)
    if len(data) != length:
        raise ValueError(f"Insufficient data for {data_type}")
    return data


def read_little_int(stream: BytesIO, length: int, data_type: str = "little-endian integert") -> int:
    data = read_stream(stream, length, data_type)
    return int.from_bytes(data, "little")


def read_big_int(stream: BytesIO, length: int, data_type: str = "big-endian integert") -> int:
    data = read_stream(stream, length, data_type)
    return int.from_bytes(data, "big")


def read_compact_size(stream: BytesIO, data_type: str = "compact-size encoded data") -> int:
    """
    Returns the integer value associated with the compact-size encoding at the head of the data stream
    """

    prefix = read_stream(stream, 1, "compact-size prefix")
    prefix_val = prefix[0]
    if prefix_val < 0xfd:
        # Single-byte value
        return prefix_val
    elif prefix_val == 0xfd:
        # Next 2 bytes as uint16 (little-endian)
        raw = read_stream(stream, 2, "0xfd prefix value")
    elif prefix_val == 0xfe:
        # Next 4 bytes as uint32 (little-endian)
        raw = read_stream(stream, 4, "0xfe prefix value")
    else:
        # prefix_val == 0xff -> Next 8 bytes as uint64 (little-endian)
        raw = read_stream(stream, 8, "0xff prefix value")
    return int.from_bytes(raw, "little")
