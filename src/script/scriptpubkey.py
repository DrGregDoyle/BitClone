"""
The ScriptPubKey class and its children
"""
import json
from abc import ABC, abstractmethod

from src.core import ScriptPubKeyError, OPCODES, SERIALIZED, get_bytes
from src.cryptography import hash160
from src.data import encode_base58check
from src.script.parser import to_asm

__all__ = ["ScriptPubKey", "P2PKH_Key", "P2PK_Key"]

# --- OPCODES --- #
_OP = OPCODES


class ScriptPubKey(ABC):
    """
    Base class for scriptPubKeys
    """
    script = None

    @classmethod
    @abstractmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
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

    def to_dict(self):
        return {
            "asm": json.loads(json.dumps(self.to_asm())),
            "address": self.address
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other):
        if isinstance(other, ScriptPubKey):
            return self.script == other.script
        raise ScriptPubKeyError(f"Cannot equate ScriptPubKey and {type(other)}")


class P2PK_Key(ScriptPubKey):
    __slots__ = ("script",)

    def __init__(self, pubkey: bytes):
        # --- Pubkey validation --- #
        if len(pubkey) not in (33, 65):
            raise ScriptPubKeyError(f"P2PK_Sig pubkey not of correct length: {len(pubkey)}. Expected one of 33, 65.")

        push_byte = _OP.get_byte("OP_PUSHBYTES_65") if len(pubkey) == 65 else _OP.get_byte("OP_PUSHBYTES_33")
        self.script = push_byte + pubkey + _OP.get_byte("OP_CHECKSIG")

    @classmethod
    def from_bytes(cls, scriptpubkey: bytes):
        lead = scriptpubkey[0]
        tail = scriptpubkey[-1]
        if tail == _OP.get_byte("OP_CHECKSIG")[0] and lead in (_OP.get_byte("OP_PUSHBYTES_33")[0],
                                                               _OP.get_byte("OP_PUSHBYTES_65")[0]):
            pubkey = scriptpubkey[1:-1]
            return cls(pubkey)
        raise ScriptPubKeyError("P2PK_Sig failed byte constructino")

    @property
    def address(self) -> str:
        """
        We hash160 the public key in the script and convert to base58, similar to P2PKH_Sig
        """
        pubkey = self.script[1:-1]
        pubkey_hash = hash160(pubkey)
        print(f"PUBKEY HASH: {pubkey_hash.hex()}")
        return encode_base58check(pubkey_hash)


class P2PKH_Key(ScriptPubKey):
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
    OP_DUP = _OP.get_byte("OP_DUP")
    OP_HASH160 = _OP.get_byte("OP_HASH160")
    OP_EQUALVERIFY = _OP.get_byte("OP_EQUALVERIFY")
    OP_CHECKSIG = _OP.get_byte("OP_CHECKSIG")
    OP_PUSHBYTES_20 = _OP.get_byte("OP_PUSHBYTES_20")

    def __init__(self, pubkey: bytes):
        pubkeyhash = hash160(pubkey)
        self.script = (self.OP_DUP + self.OP_HASH160 + self.OP_PUSHBYTES_20 + pubkeyhash + self.OP_EQUALVERIFY +
                       self.OP_CHECKSIG)
        self._pubkeyhash = pubkeyhash

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED) -> "P2PKH_Key":
        script_bytes = get_bytes(byte_stream)

        op_codes_validated = all([
            bytes([script_bytes[0]]) == cls.OP_DUP,
            bytes([script_bytes[1]]) == cls.OP_HASH160,
            bytes([script_bytes[2]]) == cls.OP_PUSHBYTES_20,
            bytes([script_bytes[-2]]) == cls.OP_EQUALVERIFY,
            bytes([script_bytes[-1]]) == cls.OP_CHECKSIG
        ])
        if op_codes_validated:
            pubkeyhash = script_bytes[3:-2]
            print(f"PUBKEYHASH: {pubkeyhash.hex()}")
            return cls.from_pubkeyhash(pubkeyhash)
        raise ScriptPubKeyError("Given scriptpubkey doesn't match P2PKH_Sig OP_CODE structure")

    @classmethod
    def from_pubkeyhash(cls, pubkeyhash: bytes) -> "P2PKH_Key":
        obj = object.__new__(cls)
        obj.script = (cls.OP_DUP + cls.OP_HASH160 + cls.OP_PUSHBYTES_20 + pubkeyhash + cls.OP_EQUALVERIFY +
                      cls.OP_CHECKSIG)
        obj._pubkeyhash = pubkeyhash
        return obj

    def address(self, testnet: bool = False) -> str:
        prefix_byte = b'\x6f' if testnet else b'\x00'
        pubkeyhash = self.script[3:-2]
        return encode_base58check(pubkeyhash, prefix_byte)

    def get_pubkeyhash(self):
        return self._pubkeyhash


# ---- TESTING --- #
if __name__ == "__main__":
    lmab_pubkeyhash_bytes = bytes.fromhex("55f44cf0dba9d62e0538b362c3ce71237e92cd94")
    lmab_p2pkh = P2PKH_Key.from_pubkeyhash(lmab_pubkeyhash_bytes)
    print(f"PUBKEYHASH: {lmab_p2pkh.get_pubkeyhash().hex()}")
    print(f"LMAB ADDRESS: {lmab_p2pkh.address()}")
    print(f"LMAB ADDRESS TESTNET: {lmab_p2pkh.address(testnet=True)}")
    # _privkey = 41
    # _pubkey = PubKey(_privkey)
    # print(f"PUBKEY: {_pubkey.to_json()}")
    #
    # _test_p2pkh = P2PKH_Sig(_pubkey.compressed())
    # _test_script = _test_p2pkh.script
    # print(f"TEST SCRIPT: {_test_script.hex()}")
    # print(f"TO ASM: {to_asm(_test_script)}")
    # fb_p2pkh = P2PKH_Sig.from_bytes(_test_p2pkh.to_bytes())
    # print(f"SCRIPTPUBKEYS EQUAL: {_test_p2pkh == fb_p2pkh}")
