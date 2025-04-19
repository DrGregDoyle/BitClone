"""
SigHash Enum class
"""
from enum import IntEnum

from src.script.stack import BTCNum


class SigHash(IntEnum):
    ALL = 1
    NONE = 2
    SINGLE = 3
    ALL_ANYONECANPAY = -127  # (0x81 interpreted as signed int)
    NONE_ANYONECANPAY = -126  # (0x82 interpreted as signed int)
    SINGLE_ANYONECANPAY = -125  # (0x83 interpreted as signed int)

    def to_byte(self) -> bytes:
        """
        Encodes the sighash integer using Bitcoin numeric encoding (BTCNum).
        """
        btc_num = BTCNum(int(self.value))
        return btc_num.bytes

    def for_hashing(self):
        """
        Encodes the sighash integer using BTCNum encoding and padded to 4 bytes
        """
        btc_num = BTCNum(int(self.value)).padded(4)
        return btc_num
