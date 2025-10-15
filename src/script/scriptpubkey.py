"""
The ScriptPubKey class and its children
"""
import json
from abc import ABC, abstractmethod

from src.core import ScriptPubKeyError, OPCODES, SERIALIZED, get_bytes, get_stream, read_little_int, read_stream
from src.cryptography import hash160
from src.data import encode_base58check
from src.script.parser import to_asm

__all__ = ["ScriptPubKey", "P2PKH_Key", "P2PK_Key", "P2MS_Key"]

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


class P2MS_Key(ScriptPubKey):
    """
    Pay 2 multisig | format:
        - a number k indicating number of required signatures
        - repeated pushbytes for all available keys
        - a number n indicating total number of keys
        - op_checkmultisig
    """
    OP_PUSHBYTES_65 = _OP.get_byte("OP_PUSHBYTES_65")
    OP_PUSHBYTES_33 = _OP.get_byte("OP_PUSHBYTES_33")
    OP_CHECKMULTISIG = _OP.get_byte("OP_CHECKMULTISIG")

    def __init__(self, pubkey_list: list, req_num: int = 0):
        total_keys = len(pubkey_list)
        req_num = req_num if req_num > 0 else total_keys  # Defaults to total number for 0 value

        # Add required_num
        script_parts = [
            _OP.get_byte(f"OP_{req_num}")
        ]

        # Add pubkeys
        for pubkey in pubkey_list:
            script_parts.append(self.OP_PUSHBYTES_33) if len(pubkey) == 33 else script_parts.append(
                self.OP_PUSHBYTES_65)
            script_parts.append(pubkey)

        # Finish up
        script_parts.extend([_OP.get_byte(f"OP_{total_keys}"), self.OP_CHECKMULTISIG])
        self.script = b''.join(script_parts)

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        script_bytes = get_bytes(byte_stream)

        # Confirm leading and tail
        lead_byte = script_bytes[0]
        tail_byte = script_bytes[-1]
        tail2_byte = script_bytes[-2]

        # OP_num (required)
        if not 0x51 <= lead_byte <= 0x60:
            raise ScriptPubKeyError("Failed OP_num leading byte opcode check for P2MS")
        # OP_num (total)
        if not 0x51 <= tail2_byte <= 0x60:
            raise ScriptPubKeyError("Failed OP_num penultimate byte opcode check for P2MS")
        # OP_CHECKMULTISIG
        if not bytes([tail_byte]) == cls.OP_CHECKMULTISIG:
            raise ScriptPubKeyError("Failed OP_CHECKMULTISIG at end of scriptpubkey")

        req_num = lead_byte - 0x50
        sig_num = tail2_byte - 0x50
        pubkey_list = []
        stream = get_stream(script_bytes[1:-2])  # Stream remaining pubkeys
        for x in range(sig_num):
            pubkey_type = read_little_int(stream, 1)
            if pubkey_type not in (33, 65):
                raise ScriptPubKeyError("Pubkey in list not of correct length")
            pubkey = read_stream(stream, pubkey_type)
            pubkey_list.append(pubkey)

        return cls(pubkey_list, req_num)

    @property
    def address(self) -> str:
        return ""


# ---- TESTING --- #
if __name__ == "__main__":
    pubkey1 = bytes.fromhex(
        "04d81fd577272bbe73308c93009eec5dc9fc319fc1ee2e7066e17220a5d47a18314578be2faea34b9f1f8ca078f8621acd4bc22897b03daa422b9bf56646b342a2")
    pubkey2 = bytes.fromhex(
        "04ec3afff0b2b66e8152e9018fe3be3fc92b30bf886b3487a525997d00fd9da2d012dce5d5275854adc3106572a5d1e12d4211b228429f5a7b2f7ba92eb0475bb1")
    pubkey3 = bytes.fromhex(
        "04b49b496684b02855bc32f5daefa2e2e406db4418f3b86bca5195600951c7d918cdbe5e6d3736ec2abf2dd7610995c3086976b2c0c7b4e459d10b34a316d5a5e7")
    _test_p2ms = P2MS_Key(pubkey_list=[pubkey1, pubkey2, pubkey3], req_num=2)
    print(f"P2MS FROM INIT: {_test_p2ms.to_asm()}")

    lmab_p2ms_key_bytes = bytes.fromhex(
        "524104d81fd577272bbe73308c93009eec5dc9fc319fc1ee2e7066e17220a5d47a18314578be2faea34b9f1f8ca078f8621acd4bc22897b03daa422b9bf56646b342a24104ec3afff0b2b66e8152e9018fe3be3fc92b30bf886b3487a525997d00fd9da2d012dce5d5275854adc3106572a5d1e12d4211b228429f5a7b2f7ba92eb0475bb14104b49b496684b02855bc32f5daefa2e2e406db4418f3b86bca5195600951c7d918cdbe5e6d3736ec2abf2dd7610995c3086976b2c0c7b4e459d10b34a316d5a5e753ae")
    _test_p2ms_key = P2MS_Key.from_bytes(lmab_p2ms_key_bytes)
    print(f"P2MS KEY FROM BYTES: {_test_p2ms_key.to_asm()}")
