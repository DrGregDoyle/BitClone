"""
Helper functions for the Serialization.from_bytes() method(s)
"""
from io import BytesIO

__all__ = ["get_stream", "read_stream", "read_little_int", "read_big_int"]


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


def read_little_int(stream: BytesIO, length: int, data_type: str = "little-endian integer") -> int:
    data = read_stream(stream, length, data_type)
    return int.from_bytes(data, "little")


def read_big_int(stream: BytesIO, length: int, data_type: str = "big-endian integer") -> int:
    data = read_stream(stream, length, data_type)
    return int.from_bytes(data, "big")
