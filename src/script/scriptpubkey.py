"""
The ScriptPubKey class and its children
"""

from abc import ABC

from src.core import ScriptPubKeyError
from src.script.parser import to_asm

# --- OPCODES --- #
OP_PUSHBYTES_33 = b'\x21'
OP_PUSHBYTES_65 = b'\x41'
OP_CHECKSIG = b'\xac'


class ScriptPubKey(ABC):
    """
    Base class for scriptPubKeys
    """
    script = None

    @classmethod
    def from_bytes(cls, *args):
        raise NotImplementedError

    def to_bytes(self):
        return self.script

    def to_asm(self):
        return to_asm(self.script)


class P2PK(ScriptPubKey):

    def __init__(self, pubkey: bytes):
        # --- Pubkey validation --- #
        if len(pubkey) not in (33, 65):
            raise ScriptPubKeyError(f"P2PK pubkey not of correct length: {len(pubkey)}. Expected one of 33, 65.")

        push_byte = OP_PUSHBYTES_33 if len(pubkey) == 33 else OP_PUSHBYTES_65
        self.script = push_byte + pubkey + OP_CHECKSIG

    @classmethod
    def from_bytes(cls, scriptpubkey: bytes):
        lead = scriptpubkey[0]
        tail = scriptpubkey[-1]
        if tail == OP_CHECKSIG[0] and lead in (OP_PUSHBYTES_33[0], OP_PUSHBYTES_65[0]):
            pubkey = scriptpubkey[1:-1]
            return cls(pubkey)
        raise ScriptPubKeyError("P2PK failed byte constructino")


# ---- TESTING --- #
if __name__ == "__main__":
    test_p2pk = P2PK(b'\x04' * 65)
    print(test_p2pk.to_asm())

    lmab_p2pk_bytes = bytes.fromhex(
        "41049464205950188c29d377eebca6535e0f3699ce4069ecd77ffebfbd0bcf95e3c134cb7d2742d800a12df41413a09ef87a80516353a2f0a280547bb5512dc03da8ac")
    lmab_p2pk = P2PK.from_bytes(lmab_p2pk_bytes)
    print(lmab_p2pk.to_asm())
