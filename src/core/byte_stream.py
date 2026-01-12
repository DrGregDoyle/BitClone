"""
Methods for deserializing byte streams

#TODO: Remove optional data_type once testing is complete
"""
from io import BytesIO
from typing import Union, Optional, Literal

from .exceptions import ReadError

__all__ = ["SERIALIZED", "BYTEORDER", "get_stream", "read_stream", "read_little_int", "read_big_int", "get_bytes",
           "read_compact_size"]

SERIALIZED = Union[bytes, BytesIO]
BYTEORDER = Literal['big', 'little']


def get_stream(byte_stream: SERIALIZED):
    """Convert bytes or BytesIO to BytesIO stream"""
    if isinstance(byte_stream, bytes):
        return BytesIO(byte_stream)
    elif isinstance(byte_stream, BytesIO):
        return byte_stream
    else:
        raise TypeError(f"Expected bytes or BytesIO but received: {type(byte_stream)}")


def get_bytes(byte_stream: SERIALIZED) -> bytes:
    """Convert BytesIO or bytes to bytes object"""
    if isinstance(byte_stream, bytes):
        return byte_stream
    elif isinstance(byte_stream, BytesIO):
        return byte_stream.getvalue()
    else:
        raise TypeError(f"Expected bytes or BytesIO but received: {type(byte_stream)}")


def read_stream(stream: BytesIO, length: int, data_type: Optional[str] = None) -> bytes:
    """Read exact number of bytes from stream with error checking"""
    data = stream.read(length)

    # Verify data integrity
    if len(data) != length:
        if data_type:
            raise ReadError(f"Error reading stream. Insufficient data. Data type: {data_type}")
        else:
            raise ReadError("Error reading stream. Insufficient data.")

    return data


def _read_int(stream: BytesIO, length: int, byteorder: BYTEORDER, data_type: Optional[str] = None) -> int:
    """Internal method to read integer from stream"""
    data = read_stream(stream, length, data_type)
    return int.from_bytes(data, byteorder)


def read_little_int(stream: BytesIO, length: int, data_type: Optional[str] = None) -> int:
    """Read little-endian integer from stream"""
    return _read_int(stream, length, "little", data_type)


def read_big_int(stream: BytesIO, length: int, data_type: Optional[str] = None) -> int:
    """Read big-endian integer from stream"""
    return _read_int(stream, length, "big", data_type)


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
