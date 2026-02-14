"""
Methods for serializing/deserializing byte streams


"""
from io import BytesIO
from typing import Union, Optional, Literal

from src.core.formats import DATA
from .exceptions import ReadError, WriteError

__all__ = ["SERIALIZED", "BYTEORDER", "get_stream", "read_stream", "read_little_int", "read_big_int", "get_bytes",
           "read_compact_size", "write_compact_size", "serialize_data", "deserialize_data"]

SERIALIZED = Union[bytes, BytesIO]
BYTEORDER = Literal['big', 'little']


# === SERIALIZATION METHODS === #
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


# === DESERIALIZATION METHODS === #
def deserialize_data(data: bytes) -> bytes:
    """
    We decode the compact size encoding of the size of the given data and then return the data.
    """
    stream = get_stream(data)
    datalen = read_compact_size(stream)
    return read_stream(stream, datalen)


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
