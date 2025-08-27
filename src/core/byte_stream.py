"""
Methods for deserializing byte streams

#TODO: Remove optional data_type once testing is complete
"""
from io import BytesIO
from typing import Union, Optional, Literal

from .exceptions import ReadError

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
