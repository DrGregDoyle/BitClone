"""
Stack helper functions
"""
from src.core import BitStackError

__all__ = ["encode_pushdata"]


def encode_pushdata(data: bytes) -> bytes:
    """
    We return the correct OP_PUSHBYTES/OP_PUSHDATA for given data
    """
    data_len = len(data)
    # OP_PUSHBYTES
    if 0x01 <= data_len <= 0x4b:
        return data_len.to_bytes(1, "little") + data
    # OP_PUSHDATA1
    elif data_len <= 0xff:
        return b'\x4c' + data_len.to_bytes(1, "little") + data
    # OP_PUSHDATA2
    elif data_len <= 0xffff:
        return b'\x4d' + data_len.to_bytes(2, "little") + data
    # OP_PUSHDATA4
    elif data_len <= 0xffffffff:
        return b'\x4e' + data_len.to_bytes(4, "little") + data
    else:
        raise BitStackError("Item of incorrect length to be pushed on stack.")
