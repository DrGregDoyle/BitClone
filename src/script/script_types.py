"""
The file for all ScriptPubKey and ScriptSig types
"""
import json
from abc import ABC
from enum import Enum

from src.script import to_asm

__all__ = ["BaseScript", "ScriptType"]

# --- OP_CODES --- #
OP_0 = b'\x00'
OP_PUSHBYTES_20 = b'\x14'
OP_PUSHBYTES_22 = b'\x16'
OP_PUSHBYTES_32 = b'\x20'
OP_PUSHBYTES_33 = b'\x21'
OP_PUSHBYTES_65 = b'\x41'
OP_1 = b'\x51'
OP_CHECKSIG = b'\xac'
OP_CHECKMULTISIG = b'\xae'
OP_DUP = b'\x76'
OP_EQUAL = b'\x87'
OP_EQUALVERIFY = b'\x88'
OP_HASH160 = b'\xa9'

# --- CONSTANTS --- #
PUBKEY_LENGTHS = [33, 65]


class ScriptType(Enum):
    P2PK = "P2PK"
    P2PKH = "P2PKH"
    P2MS = "P2MS"
    P2SH = "P2SH"
    P2SH_P2WPKH = "P2SH-P2WPKH"
    P2SH_P2WSH = "P2SH-P2WSH"
    P2WPKH = "P2WPKH"
    P2WSH = "P2WSH"
    P2TR = "P2TR"


class BaseScript(ABC):
    __slots__ = ("script",)
    script_type: ScriptType = None

    def to_bytes(self) -> bytes:
        return self.script

    def to_asm(self):
        return to_asm(self.script)

    def to_dict(self) -> dict:
        return {"asm": json.loads(json.dumps(self.to_asm())),
                "script": self.script.hex()}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
