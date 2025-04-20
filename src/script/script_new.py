"""
The classes for Bitcoin Script objects
"""
from enum import Enum, IntEnum

from src.script.stack import BTCNum


class ScriptType(Enum):
    P2PK = "p2pk"
    P2PKH = "p2pkh"
    P2SH = "p2sh"
    P2WPKH = "p2wpkh"
    P2WSH = "p2wsh"
    P2TR = "p2tr"
    P2MS = "p2ms"


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


class Script:
    """
    Class for commonalities between ScriptPubKey and ScriptSig
    """
    pass


class ScriptPubKey(Script):
    """
    Class used to generate ScriptPubKey objects for use in Bitclone
    """
    pass


class ScriptSig(Script):
    """
    Class used to generate a ScriptSig object for use in Bitcoin
    """
    pass
