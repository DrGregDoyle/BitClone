"""
The file for all ScriptPubKey and ScriptSig types
"""
import json
from abc import ABC, abstractmethod

from src.core import SERIALIZED, ScriptPubKeyError, get_bytes, get_stream, read_little_int, read_stream, PubKeyError, \
    ScriptSigError
from src.cryptography import hash160
from src.data import encode_base58check, encode_bech32, get_unbalanced_merkle_root, TweakPubkey, PubKey
from src.script import to_asm
from src.script.stack_ops import encode_pushdata

__all__ = ["P2PK_Key", "P2PKH_Key", "P2MS_Key", "P2SH_Key", "P2WPKH_Key", "P2WSH_Key", "P2TR_Key", "P2PK_Sig",
           "P2PKH_Sig", "P2MS_Sig", "P2SH_Sig", "P2SH_P2WPKH_Sig", "ScriptPubKey", "ScriptSig"]

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


class BaseScript(ABC):
    __slots__ = ("script",)

    def to_bytes(self) -> bytes:
        return self.script

    def to_asm(self):
        return to_asm(self.script)

    def to_dict(self) -> dict:
        return {"asm": json.loads(json.dumps(self.to_asm())),
                "script": self.script.hex()}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# --- ScriptPubKeys --- #
class ScriptPubKey(BaseScript, ABC):
    """
    The parent class for all ScriptPubKeys
    """

    @classmethod
    @abstractmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        raise NotImplementedError

    @property
    @abstractmethod
    def address(self) -> str:
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def matches(cls, b: bytes) -> bool:
        """Return True if the given script matches this type"""
        raise NotImplementedError

    def __eq__(self, other):
        if isinstance(other, ScriptPubKey):
            return self.script == other.script
        raise ScriptPubKeyError(f"Cannot equate ScriptPubKey and {type(other)}")


class P2PK_Key(ScriptPubKey):
    """
    Pay 2 Public Key | OP_PUSHBYTES || pubkey || OP_CHECKSIG
    """

    def __init__(self, pubkey: bytes):

        # --- Validation
        if len(pubkey) not in PUBKEY_LENGTHS:
            raise ScriptPubKeyError("Given Pubkey not of allowed length")

        # --- Create script
        op_code = OP_PUSHBYTES_33 if len(pubkey) == 33 else OP_PUSHBYTES_65
        self.script = op_code + pubkey + OP_CHECKSIG

    @classmethod
    def matches(cls, b: bytes) -> bool:
        return all([
            len(b) - 2 in PUBKEY_LENGTHS,
            b[0] in (OP_PUSHBYTES_33[0], OP_PUSHBYTES_65[0]),
            b[-1] == OP_CHECKSIG[0]
        ])

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        script_bytes = get_bytes(byte_stream)
        if cls.matches(script_bytes):
            obj = cls.__new__(P2PK_Key)
            obj.script = script_bytes
            return obj
        raise ScriptPubKeyError("Byte stream does not match P2PK type")

    @property
    def address(self) -> str:
        """
        We hash160 the public key in the script and convert to base58, similar to P2PKH_Sig
        """
        pubkey = self.script[1:-1]
        pubkey_hash = hash160(pubkey)
        return encode_base58check(pubkey_hash)


class P2PKH_Key(ScriptPubKey):
    """
    Pay 2 Pubkey Hash | OP_DUP || OP_HASH160 || OP_PUSHBYTES_20 || pubkeyhash || OP_EQUALVERIFY || OP_CHECKSIG
    """

    def __init__(self, pubkey: bytes):
        pubkeyhash = hash160(pubkey)
        self.script = OP_DUP + OP_HASH160 + OP_PUSHBYTES_20 + pubkeyhash + OP_EQUALVERIFY + OP_CHECKSIG

    @classmethod
    def matches(cls, b: bytes) -> bool:
        truth_list = [
            b[0] == OP_DUP[0],
            b[1] == OP_HASH160[0],
            b[2] == OP_PUSHBYTES_20[0],
            b[-2] == OP_EQUALVERIFY[0],
            b[-1] == OP_CHECKSIG[0]
        ]
        return all(truth_list)

    @classmethod
    def from_bytes(cls, script_bytes: bytes) -> "P2PKH_Key":
        if cls.matches(script_bytes):
            obj = object.__new__(cls)
            obj.script = script_bytes
            return obj
        raise ScriptPubKeyError("Given scriptpubkey doesn't match P2PKH_Sig OP_CODE structure")

    @classmethod
    def from_pubkeyhash(cls, pubkeyhash: bytes) -> "P2PKH_Key":
        obj = object.__new__(cls)
        obj.script = OP_DUP + OP_HASH160 + OP_PUSHBYTES_20 + pubkeyhash + OP_EQUALVERIFY + OP_CHECKSIG
        return obj

    @property
    def address(self, testnet: bool = False) -> str:
        prefix_byte = b'\x6f' if testnet else b'\x00'
        pubkeyhash = self.script[3:-2]
        return encode_base58check(pubkeyhash, prefix_byte)


class P2MS_Key(ScriptPubKey):

    def __init__(self, pubkeys: list, min_num: int = 0):
        pubkey_num = len(pubkeys)
        min_num = pubkey_num if min_num == 0 else min_num

        # --- Validation
        if not all([len(pubkey) in PUBKEY_LENGTHS for pubkey in pubkeys]):
            raise ScriptPubKeyError("Given pubkeys not in correct format")

        # --- Construct script
        op_min = bytes([0x50 + min_num])
        op_tot = bytes([0x50 + pubkey_num])

        script_parts = [op_min]
        for pubkey in pubkeys:
            script_parts.append(OP_PUSHBYTES_33) if len(pubkey) == 33 else script_parts.append(OP_PUSHBYTES_65)
            script_parts.append(pubkey)
        script_parts.extend([op_tot, OP_CHECKMULTISIG])

        self.script = b''.join(script_parts)

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        script_bytes = get_bytes(byte_stream)

        if not cls.matches(script_bytes):
            raise ScriptPubKeyError("Failed to match P2MS structure")

        req_num = script_bytes[0] - 0x50  # Required number of signatures
        sig_num = script_bytes[-2] - 0x50  # Total number of signatures
        pubkey_list = []
        stream = get_stream(script_bytes[1:-2])  # Stream remaining pubkeys
        for x in range(sig_num):
            pubkey_type = read_little_int(stream, 1)
            if pubkey_type not in PUBKEY_LENGTHS:
                raise ScriptPubKeyError("Pubkey in list not of correct length")
            pubkey = read_stream(stream, pubkey_type)
            pubkey_list.append(pubkey)

        return cls(pubkey_list, req_num)

    @property
    def address(self) -> str:
        return ""

    @classmethod
    def matches(cls, b: bytes) -> bool:
        # Confirm leading and tail
        lead_byte = b[0]
        tail_byte = b[-1]
        tail2_byte = b[-2]

        truth_list = [
            0x51 <= lead_byte <= 0x60,  # OP_num (required)
            0x51 <= tail2_byte <= 0x60,  # OP_num (total)
            bytes([tail_byte]) == OP_CHECKMULTISIG  # OP_CHECKMULTISIG
        ]

        return all(truth_list)


class P2SH_Key(ScriptPubKey):
    def __init__(self, hash_data: bytes):
        # Validate data is 20 byte digest
        if len(hash_data) != 20:
            raise ScriptPubKeyError("Given hash data not a 20-byte digest")

        self.script = OP_HASH160 + OP_PUSHBYTES_20 + hash_data + OP_EQUAL

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        script_bytes = get_bytes(byte_stream)

        # Verify
        lead_byte = script_bytes[0]
        second_byte = script_bytes[1]
        last_byte = script_bytes[-1]

        if not all([lead_byte == OP_HASH160[0], second_byte == OP_PUSHBYTES_20[0], last_byte == OP_EQUAL[
            0]]):
            raise ScriptPubKeyError("Failed OP_Code structure for P2SH ScriptPubKey")

        return cls(script_bytes[2:-1])

    @property
    def address(self, testnet: bool = False) -> str:
        script_hash = self.script[2:-1]
        prefix = b'\x05' if not testnet else b'\xc4'

        return encode_base58check(script_hash, prefix)

    @classmethod
    def matches(cls, b: bytes) -> bool:
        truth_list = [
            b[0] == OP_HASH160[0],  # OP_HASH160
            b[1] == OP_PUSHBYTES_20[0],  # OP_PUSHBYTES_20
            b[-1] == OP_EQUAL[0],  # OP_EQUAL
            len(b) == 23  # ScriptPubKey has expected hash length
        ]
        return all(truth_list)


class P2WPKH_Key(ScriptPubKey):
    """
    For use in P2SH-P2WPKH and P2WPKH itself
    """

    def __init__(self, pubkeyhash: bytes):
        # Validate
        if len(pubkeyhash) != 20:
            raise ScriptPubKeyError("Given pubkeyhash not 20 bytes")
        self.script = OP_0 + OP_PUSHBYTES_20 + pubkeyhash

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        script_bytes = get_bytes(byte_stream)

        if cls.matches(script_bytes):
            return cls(script_bytes[2:])
        raise ScriptPubKeyError("Given byte digest doesn't match P2WPKH opcode structure")

    @classmethod
    def matches(cls, b: bytes) -> bool:
        truthlist = [
            b[0] == OP_0[0],
            b[1] == OP_PUSHBYTES_20[0],
            len(b[2:]) == 20
        ]
        return all(truthlist)

    @classmethod
    def from_pubkey(cls, pubkey: bytes):
        """
        Given a Pubkey obj, we can hash the compressed pubkey and return the instance
        """
        # Pubkey must be a 33 byte compressed public key
        if len(pubkey) != 33:
            raise ScriptPubKeyError("P2WPKH only uses compressed public keys")
        pubkeyhash = hash160(pubkey)
        return cls(pubkeyhash)

    @property
    def address(self) -> str:
        # The encode_bech32 function only takes the SCRIPTPUBKEY, and the witness version is submitted separately
        scriptpubkey = self.script[2:]
        return encode_bech32(scriptpubkey, witver=0)


class P2WSH_Key(ScriptPubKey):
    """
    Pay To Witness Script Hash
    """

    def __init__(self, script_hash: bytes):
        # Validation
        if len(script_hash) != 32:
            raise ScriptPubKeyError("P2WSH Key must be 32 bytes")

        self.script = OP_0 + OP_PUSHBYTES_32 + script_hash

    @classmethod
    def matches(cls, b: bytes) -> bool:
        lead_byte = b[0]
        first_byte = b[1]
        scripthash_len = len(b[2:])
        truth_list = [
            lead_byte == OP_0[0],
            first_byte == OP_PUSHBYTES_32[0],
            scripthash_len == 32
        ]
        return all(truth_list)

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        script_bytes = get_bytes(byte_stream)

        if cls.matches(script_bytes):
            return cls(script_bytes[2:])
        raise ScriptPubKeyError("Data failed P2WSH opcode structure")

    @property
    def address(self) -> str:
        scriptpubkey = self.script[2:]
        return encode_bech32(scriptpubkey, witver=0)


class P2TR_Key(ScriptPubKey):
    """
    A ScriptPubKey for the Key Path Spend method in Taproot
    """

    def __init__(self, xonly_pubkey: bytes, scripts: list[bytes] = None):
        merkle_root = get_unbalanced_merkle_root(scripts) if scripts else b''
        tweakpubkey = TweakPubkey(xonly_pubkey, merkle_root)

        self.script = OP_1 + OP_PUSHBYTES_32 + tweakpubkey.tweaked_pubkey.x_bytes()

    @classmethod
    def matches(cls, b: bytes) -> bool:
        truth_list = [
            b[0] == OP_1[0],
            b[1] == OP_PUSHBYTES_32[0],
            len(b[2:]) == 32
        ]
        return all(truth_list)

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        script_bytes = get_bytes(byte_stream)

        if cls.matches(script_bytes):
            try:
                _ = PubKey.from_xonly(script_bytes[2:])
            except PubKeyError as e:
                raise f"Given script fails x-only public key validation: {e}"

            obj = object.__new__(cls)
            obj.script = script_bytes
            return obj
        raise PubKeyError("Script bytes do not match opcode syntax for P2TR")

    @property
    def address(self) -> str:
        return encode_bech32(self.script[2:], hrp='bc', witver=1)  # OP_1


# --- ScriptSigs --- #
class ScriptSig(BaseScript, ABC):
    """
    The parent class for all ScriptSigs
    """

    @classmethod
    @abstractmethod
    def from_bytes(cls, scriptsig: bytes):
        """All subclasses must implement this"""
        raise NotImplementedError("Missing from_bytes construction")

    @classmethod
    @abstractmethod
    def matches(cls, b: bytes) -> bool:
        """Return True if the given script matches this type"""
        raise NotImplementedError


class P2PK_Sig(ScriptSig):
    """
    Script = OP_PUSHBYTES + signature

    ECDSA signatures are always ≤74 bytes (71-73 bytes DER + 1 byte sighash),
    so we never need OP_PUSHDATA opcodes.
    """

    def __init__(self, sig: bytes):
        self.script = encode_pushdata(sig)

    @classmethod
    def matches(cls, b: bytes) -> bool:
        script_len = b[0]
        return script_len == len(b[1:])

    @classmethod
    def from_bytes(cls, scriptsig: bytes):
        if cls.matches(scriptsig):
            obj = object.__new__(cls)
            obj.script = scriptsig
            return obj
        raise ScriptSigError("Incorrect format for P2PK ScriptSig")


class P2PKH_Sig(ScriptSig):
    """
    Script = OP_PUSHBYTES + signature + OP_PUSHBYTES + public_key

    NOTES
        -pubkey can be either compressed or uncompressed (33 bytes or 65 bytes, resp)
        -Whatever form the pubkey uses in the ScriptSig needs to be the same one which generates the pubkeyhash in
        the ScriptPubKey
    """

    def __init__(self, sig: bytes, pubkey: bytes):
        # Verify pubkey length
        if len(pubkey) not in PUBKEY_LENGTHS:
            raise ScriptSigError("Given public key not of allowable length")

        # Construct: <sig_len> <sig> <pubkey_len> <pubkey>
        self.script = encode_pushdata(sig) + encode_pushdata(pubkey)  # Will raise errors if lengths incorrect

    @classmethod
    def matches(cls, b: bytes) -> bool:
        sig_len = b[0]
        offset = 1 + sig_len
        sig = b[1:offset]
        pubkey_len = b[offset]
        pubkey = b[offset + 1: offset + 1 + pubkey_len]

        truth_list = [
            0x01 <= sig_len <= 0x4b,
            len(sig) == sig_len,
            len(pubkey) == pubkey_len
        ]
        return all(truth_list)

    @classmethod
    def from_bytes(cls, scriptsig: bytes):
        if cls.matches(scriptsig):
            obj = object.__new__(cls)
            obj.script = scriptsig
            return obj
        raise ScriptSigError("Given ScriptSig doesn't match P2PKH structure")


class P2MS_Sig(ScriptSig):
    """
    Pay 2 multisig, takes in list of signatures and returns OP_PUSHBYTES ahead of each signature.
    We include an additional OP_0 due to OP_CHECKMULTISIG bug. (BIP-147)
    P2MS | OP_0 + #signatures * (OP_PUSHBYTES + SIGNATURE)
    """

    def __init__(self, signatures: list):
        self.script = OP_0  # BIP-147
        for sig in signatures:
            self.script += encode_pushdata(sig)

    @classmethod
    def matches(cls, b: bytes) -> bool:
        # Check NULLDUMMY
        if b[0] != 0:
            return False

        # Check siglength for each sig
        signatures = []
        scriptsig = b[1:]
        while True:
            opcode = scriptsig[0]
            if not (0x01 <= opcode <= 0x4b):
                return False
            signatures.append(scriptsig[1:1 + opcode])
            scriptsig = scriptsig[1 + opcode:]
            if scriptsig == b'':
                break
        return len(signatures) >= 1

    @classmethod
    def from_bytes(cls, scriptsig: bytes):
        if cls.matches(scriptsig):
            obj = object.__new__(cls)
            obj.script = scriptsig
            return obj
        raise ScriptSigError("Given ScriptSig doesn't match P2MS structure.")


class P2SH_Sig(ScriptSig):
    """
    The P2SH consists of two parts:
        -The signature(s) necessary to unlock the redeem script (which gets hash160'ed in the scriptpubkey)
        -A data push of the redeem script
    """

    def __init__(self, signatures: bytes | list[bytes], redeem_script: bytes):
        sig_bytes = b''.join([encode_pushdata(sig) for sig in signatures]) if isinstance(signatures,
                                                                                         list) else signatures
        self.script = sig_bytes + encode_pushdata(redeem_script)

    @classmethod
    def matches(cls, b: bytes) -> bool:
        if not b:
            return False

        length = len(b)

        # Walk backwards to find the last small push
        for i in range(length - 1, -1, -1):
            push_len = b[i]

            # Small push only (what encode_pushdata uses for short scripts)
            if 1 <= push_len <= 0x4b:
                remaining_bytes = length - (i + 1)
                if remaining_bytes == push_len:
                    # This means b[i] is OP_PUSHBYTES for the redeem_script,
                    # and the tail is exactly that many bytes.
                    return True

        return False

    @classmethod
    def from_bytes(cls, scriptsig: bytes):
        if not cls.matches(scriptsig):
            raise ScriptSigError("Given ScriptSig doesn't match P2SH structure.")

        obj = object.__new__(cls)
        obj.script = scriptsig
        return obj


class P2SH_P2WPKH_Sig(ScriptSig):
    """
    ScriptPubKey = P2SH_Key
    But we unlock using both ScriptSig and WitnessField
    """

    def __init__(self, p2wpkh_key: bytes | P2WPKH_Key):
        self.script = OP_PUSHBYTES_22 + (p2wpkh_key.script if isinstance(p2wpkh_key, P2WPKH_Key) else p2wpkh_key)

    @classmethod
    def matches(cls, b: bytes) -> bool:
        return OP_PUSHBYTES_22[0] == b[0]

    @classmethod
    def from_bytes(cls, scriptsig: bytes):
        if not cls.matches(scriptsig):
            raise ScriptSigError("Given data does not match P2SH-P2WPKH opcode syntax")
        obj = object.__new__(cls)
        obj.script = scriptsig
        return obj
