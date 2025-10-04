"""
ScriptType enum class
"""
from enum import Enum

__all__ = ["ScriptType"]


class ScriptType(Enum):
    P2PK = "P2PK"
    P2PKH = "P2PKH"
    P2MS = "P2MS"
    P2SH = "P2SH"
    P2SH_P2WPkH = "P2SH_P2WPKH"
    P2SH_P2WSH = "P2SH_P2WSH"
    P2WPKH = "P2WPKH"
    P2WSH = "P2WSH"
    P2TR = "P2TR"
    CUSTOM = "CUSTOM"
