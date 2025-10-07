"""
The ScriptPubKey class and its children
"""

from abc import ABC, abstractmethod

from src.core import ScriptPubKeyError, OPCODES
from src.cryptography import hash160
from src.data import encode_base58check
from src.script.parser import to_asm

# --- OPCODES --- #
_OP = OPCODES


class ScriptPubKey(ABC):
    """
    Base class for scriptPubKeys
    """
    script = None

    @classmethod
    @abstractmethod
    def from_bytes(cls, *args):
        raise NotImplementedError

    @property
    @abstractmethod
    def address(self) -> str:
        """
        Returns the associated address with the ScriptPubKey
        """
        raise NotImplementedError

    def to_bytes(self):
        return self.script

    def to_asm(self):
        return to_asm(self.script)


class P2PK(ScriptPubKey):
    __slots__ = ("script",)

    def __init__(self, pubkey: bytes):
        # --- Pubkey validation --- #
        if len(pubkey) not in (33, 65):
            raise ScriptPubKeyError(f"P2PK pubkey not of correct length: {len(pubkey)}. Expected one of 33, 65.")

        push_byte = _OP.OP_PUSHBYTES_33 if len(pubkey) == 33 else _OP.OP_PUSHBYTES_33
        self.script = push_byte + pubkey + _OP.OP_CHECKSIG

    @classmethod
    def from_bytes(cls, scriptpubkey: bytes):
        lead = scriptpubkey[0]
        tail = scriptpubkey[-1]
        if tail == _OP.OP_CHECKSIG[0] and lead in (_OP.OP_PUSHBYTES_33[0], _OP.OP_PUSHBYTES_65[0]):
            pubkey = scriptpubkey[1:-1]
            return cls(pubkey)
        raise ScriptPubKeyError("P2PK failed byte constructino")

    @property
    def address(self) -> str:
        """
        We hash160 the public key in the script and convert to base58, similar to P2PKH
        """
        pubkey = self.script[1:-1]
        pubkey_hash = hash160(pubkey)
        print(f"PUBKEY HASH: {pubkey_hash.hex()}")
        return encode_base58check(pubkey_hash)


class P2PKH(ScriptPubKey):
    """
    ScriptPubKey:
        OP_DUP || OP_HASH160 || pubkeyhash || OP_EQUALVERIFY || CHECKSIG
    ScriptScig:
        OP_PUSHBYTES || signature || OP_PUSHBYTES || pubkey

    Scriptsig acts on stack by pushing first signature and pubkey
    Scriptpubkey acts on stack by:
        -OP_DUP - duplicates top of stack (the pubkey)
        -OP_HASH160 - create pubkeyhash and push to stacc
        -pubkeyhash - push pubkeyhash to stack
        -OP_EQUALVERIFY - pop the top two elements and compare them, stop if not equal
        -OP_CHECKSIG - pop the signature and verify it, push 1 if true, 0 otherwise
    """

    def __init__(self, pubkey: bytes):
        pubkeyhash = hash160(pubkey)
        self.script = _OP.OP_DUP + _OP.OP_HASH160 + pubkeyhash + _OP.OP_EQUALVERIFY + _OP.OP_CHECKSIG


# ---- TESTING --- #
if __name__ == "__main__":
    lmab_p2pk_bytes = bytes.fromhex(
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac")
    lmab_p2pk = P2PK.from_bytes(lmab_p2pk_bytes)
    print(lmab_p2pk.to_asm())
    print(f"ADDRESS: {lmab_p2pk.address}")
