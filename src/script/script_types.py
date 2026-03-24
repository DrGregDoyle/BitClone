"""
The file for all ScriptPubKey and ScriptSig types
"""
import json
from abc import ABC
from enum import Enum

from src.script import to_asm

__all__ = ["BaseScript", "ScriptType"]


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
