"""
The ScriptSig class and its children
"""

from abc import ABC

from src.core import ScriptSigError
from src.script.parser import to_asm

# --- OPCODES --- #
OP_PUSHBYTES_33 = b'\x21'
OP_PUSHBYTES_65 = b'\x41'
OP_CHECKSIG = b'\xac'


class ScriptSig(ABC):
    """
    Base class for scriptPubKeys
    """
    script = None

    def to_asm(self):
        return to_asm(self.script)


class P2PK(ScriptSig):

    def __init__(self, sig: bytes):
        self.script = len(sig).to_bytes(1, "big") + sig

    @classmethod
    def from_bytes(cls, scriptsig: bytes):
        scriptsig_len = scriptsig[0]
        if scriptsig_len == len(scriptsig[1:]) and 0x00 <= scriptsig_len <= 0x4b:
            return cls(scriptsig[1:])
        raise ScriptSigError("Given signature has incorrect format for P2PK")


# --- TESTING
if __name__ == "__main__":
    test_scriptsig_bytes = bytes.fromhex(
        "483045022100c219a522e65ca8500ebe05a70d5a49d840ccc15f2afa4ee9df783f06b2a322310220489a46c37feb33f52c586da25c70113b8eea41216440eb84771cb67a67fdb68c01")

    test_ss = P2PK.from_bytes(test_scriptsig_bytes)
    print(test_ss.to_asm())
