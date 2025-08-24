"""
SigHash Enum class
"""
from enum import IntEnum

__all__ = ["SigHash"]


class SigHash(IntEnum):
    DEFAULT = 0x00
    ALL = 0x01
    NONE = 0x02
    SINGLE = 0x03
    ALL_ANYONECANPAY = 0x81  # (0x81 interpreted as signed int)
    NONE_ANYONECANPAY = 0x82  # (0x82 interpreted as signed int)
    SINGLE_ANYONECANPAY = 0x83  # (0x83 interpreted as signed int)

    def to_byte(self) -> bytes:
        """
        Encodes the sighash integer using Bitcoin numeric encoding
        """
        return self.value.to_bytes(1, "little")

    def for_hashing(self):
        """
        Encodes the sighash integer using BTCNum encoding and padded to 4 bytes
        """
        return self.value.to_bytes(4, "little")
