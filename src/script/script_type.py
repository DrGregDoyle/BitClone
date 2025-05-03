from enum import Enum


class ScriptType(Enum):
    P2PK = "P2PK"
    P2PKH = "P2PKH"
    P2MS = "P2MS"
    P2SH = "P2SH"
    P2WPKH = "P2WPKH"
    P2WSH = "P2WSH"
    P2TR = "P2TR"
    CUSTOM = "CUSTOM"
