"""
The ScriptPubKey class and its children
SCRIPTPUBKEY = LOCKING SCRIPT
"""
import json
from abc import ABC, abstractmethod

from src.core import ScriptPubKeyError, OPCODES, SERIALIZED, get_bytes, get_stream, read_little_int, read_stream, \
    PubKeyError
from src.cryptography import taptweak_hash
from src.data import encode_base58check, encode_bech32, hash160, PubKey
from src.script.parser import to_asm
from src.script.taproot import get_unbalanced_merkle_root

__all__ = ["ScriptPubKey", "P2PKH_Key", "P2PK_Key", "P2MS_Key", "P2SH_Key", "P2WPKH_Key", "P2WSH_Key", "P2TR_Key"]

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

    @classmethod
    @abstractmethod
    def matches(cls, b: bytes) -> bool:
        """Return True if the given script matches this type"""
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
    """
    OP_PUSHBYTES_33/65 || pubkey || OP_CHECKSIG
    *pubkey is either 33 bytes compressed or 65 bytes uncompressed
    """
    OP_PUSHBYTES_33 = _OP.get_byte("OP_PUSHBYTES_33")
    OP_PUSHBYTES_65 = _OP.get_byte("OP_PUSHBYTES_65")
    OP_CHECKSIG = _OP.get_byte("OP_CHECKSIG")
    __slots__ = ("script",)

    def __init__(self, pubkey: bytes):
        # --- Pubkey validation --- #
        if len(pubkey) not in (33, 65):
            raise ScriptPubKeyError(f"P2PK_Sig pubkey not of correct length: {len(pubkey)}. Expected one of 33, 65.")

        push_byte = _OP.get_byte("OP_PUSHBYTES_65") if len(pubkey) == 65 else _OP.get_byte("OP_PUSHBYTES_33")
        self.script = push_byte + pubkey + _OP.get_byte("OP_CHECKSIG")

    @classmethod
    def from_bytes(cls, scriptpubkey: bytes):
        # Check type
        if cls.matches(scriptpubkey):
            pubkey = scriptpubkey[1:-1]
            return cls(pubkey)
        raise ScriptPubKeyError("Given script doesn't match P2PK")

    @property
    def address(self) -> str:
        """
        We hash160 the public key in the script and convert to base58, similar to P2PKH_Sig
        """
        pubkey = self.script[1:-1]
        pubkey_hash = hash160(pubkey)
        print(f"PUBKEY HASH: {pubkey_hash.hex()}")
        return encode_base58check(pubkey_hash)

    @classmethod
    def matches(cls, b: bytes) -> bool:

        truth_list = [
            len(b) in (35, 67),  # Check length
            b[0] in (cls.OP_PUSHBYTES_33[0], cls.OP_PUSHBYTES_65[0]),  # Check OP_PUSHBYTES
            b[-1] == cls.OP_CHECKSIG[0]  # Check OP_CHECKSIG
        ]
        return all(truth_list)


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

    __slots__ = ("script",)

    def __init__(self, pubkey: bytes):
        pubkeyhash = hash160(pubkey)
        self.script = (self.OP_DUP + self.OP_HASH160 + self.OP_PUSHBYTES_20 + pubkeyhash + self.OP_EQUALVERIFY +
                       self.OP_CHECKSIG)
        self._pubkeyhash = pubkeyhash

    @classmethod
    def from_bytes(cls, script_bytes: bytes) -> "P2PKH_Key":
        if cls.matches(script_bytes):
            pubkeyhash = script_bytes[3:-2]
            return cls.from_pubkeyhash(pubkeyhash)
        raise ScriptPubKeyError("Given scriptpubkey doesn't match P2PKH_Sig OP_CODE structure")

    @classmethod
    def from_pubkeyhash(cls, pubkeyhash: bytes) -> "P2PKH_Key":
        obj = object.__new__(cls)
        obj.script = (cls.OP_DUP + cls.OP_HASH160 + cls.OP_PUSHBYTES_20 + pubkeyhash + cls.OP_EQUALVERIFY +
                      cls.OP_CHECKSIG)
        obj._pubkeyhash = pubkeyhash
        return obj

    @property
    def address(self, testnet: bool = False) -> str:
        prefix_byte = b'\x6f' if testnet else b'\x00'
        pubkeyhash = self.script[3:-2]
        return encode_base58check(pubkeyhash, prefix_byte)

    def get_pubkeyhash(self):
        return self._pubkeyhash

    @classmethod
    def matches(cls, b: bytes) -> bool:
        truth_list = [
            b[0] == cls.OP_DUP[0],
            b[1] == cls.OP_HASH160[0],
            b[2] == cls.OP_PUSHBYTES_20[0],
            b[-2] == cls.OP_EQUALVERIFY[0],
            b[-1] == cls.OP_CHECKSIG[0]
        ]
        return all(truth_list)


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

    __slots__ = ("script",)

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

        if not cls.matches(script_bytes):
            raise ScriptPubKeyError("Failed to match P2MS structure")

        req_num = script_bytes[0] - 0x50  # Required number of signatures
        sig_num = script_bytes[-2] - 0x50  # Total number of signatures
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

    @classmethod
    def matches(cls, b: bytes) -> bool:
        # Confirm leading and tail
        lead_byte = b[0]
        tail_byte = b[-1]
        tail2_byte = b[-2]

        truth_list = [
            0x51 <= lead_byte <= 0x60,  # OP_num (required)
            0x51 <= tail2_byte <= 0x60,  # OP_num (total)
            bytes([tail_byte]) == cls.OP_CHECKMULTISIG  # OP_CHECKMULTISIG
        ]

        return all(truth_list)


class P2SH_Key(ScriptPubKey):
    """
    P2SH ScriptPubKey contains the HASH of another locking script, surrounded by HASH160 and EQUAL opcodes
    OP_HASH160 || OP_PUSHBYTES_20 || HASH || OP_EQUAL
    """
    OP_HASH160 = _OP.get_byte("OP_HASH160")
    OP_PUSHBYTES_20 = _OP.get_byte("OP_PUSHBYTES_20")
    OP_EQUAL = _OP.get_byte("OP_EQUAL")

    __slots__ = ("script",)

    def __init__(self, hash_data: bytes):
        # Validate data is 20 byte digest
        if len(hash_data) != 20:
            raise ScriptPubKeyError("Given hash data not a 20-byte digest")

        self.script = self.OP_HASH160 + self.OP_PUSHBYTES_20 + hash_data + self.OP_EQUAL

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        script_bytes = get_bytes(byte_stream)

        # Verify
        lead_byte = script_bytes[0]
        second_byte = script_bytes[1]
        last_byte = script_bytes[-1]

        if not all([lead_byte == cls.OP_HASH160[0], second_byte == cls.OP_PUSHBYTES_20[0], last_byte == cls.OP_EQUAL[
            0]]):
            raise ScriptPubKeyError("Failed OP_Code structure for P2SH ScriptPubKey")

        return cls(script_bytes[2:-1])

    @property
    def address(self) -> str:
        script_hash = self.script[2:-1]
        prefix = b'\x05'

        return encode_base58check(script_hash, prefix)

    @classmethod
    def matches(cls, b: bytes) -> bool:
        truth_list = [
            b[0] == cls.OP_HASH160[0],  # OP_HASH160
            b[1] == cls.OP_PUSHBYTES_20[0],  # OP_PUSHBYTES_20
            b[-1] == cls.OP_EQUAL[0],  # OP_EQUAL
            len(b) == 23  # ScriptPubKey has expected hash length
        ]
        return all(truth_list)


class P2WPKH_Key(ScriptPubKey):
    """
    For use in P2SH-P2WPKH and P2WPKH itself
    """
    OP_0 = b'\x00'  # Version byte
    OP_PUSHBYTES_20 = _OP.get_byte("OP_PUSHBYTES_20")

    def __init__(self, pubkeyhash: bytes):
        # Validate
        if len(pubkeyhash) != 20:
            raise ScriptPubKeyError("Given pubkeyhash not 20 bytes")
        self.script = self.OP_0 + self.OP_PUSHBYTES_20 + pubkeyhash

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        script_bytes = get_bytes(byte_stream)

        if cls.matches(script_bytes):
            return cls(script_bytes[2:])
        raise ScriptPubKeyError("Given byte digest doesn't match P2WPKH opcode structure")

    @classmethod
    def matches(cls, b: bytes) -> bool:
        truthlist = [
            b[0] == cls.OP_0[0],
            b[1] == cls.OP_PUSHBYTES_20[0],
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
    OP_0 = b'\x00'
    OP_PUSHBYTES_32 = _OP.get_byte("OP_PUSHBYTES_32")

    def __init__(self, script_hash: bytes):
        # Validation
        if len(script_hash) != 32:
            raise ScriptPubKeyError("P2WSH Key must be 32 bytes")

        self.script = self.OP_0 + self.OP_PUSHBYTES_32 + script_hash

    @classmethod
    def matches(cls, b: bytes) -> bool:
        lead_byte = b[0]
        first_byte = b[1]
        scripthash_len = len(b[2:])
        truth_list = [
            lead_byte == cls.OP_0[0],
            first_byte == cls.OP_PUSHBYTES_32[0],
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
    OP_1 = _OP.get_byte("OP_1")
    OP_PUSHBYTES_32 = _OP.get_byte("OP_PUSHBYTES_32")

    # TODO: Add version_byte = b'\xc0 to formats.py

    def __init__(self, xonly_pubkey: bytes, scripts: list[bytes] = None, leaf_version: bytes = b'\xc0'):
        # Validation
        try:
            valid_pubkey = PubKey.from_xonly(xonly_pubkey)
        except PubKeyError as e:
            raise f"Invalid x-only pubkey: {e}"

        # Check for key-path or script path
        self._scripts = scripts
        if scripts is None:
            # Key-path
            self._merkle_root = b''
        else:
            # Script-path
            self._merkle_root = get_unbalanced_merkle_root(scripts, version_byte=leaf_version)
        self._tweak = taptweak_hash(valid_pubkey.x_bytes() + self._merkle_root)
        self._tweaked_pubkey = valid_pubkey.tweak_pubkey(self._tweak)

        self.script = self.OP_1 + self.OP_PUSHBYTES_32 + self._tweaked_pubkey.x_bytes()

    def get_tweak(self):
        return self._tweak

    def get_merkle_root(self):
        return self._merkle_root

    def get_tweaked_pubkey(self):
        return self._tweaked_pubkey

    @classmethod
    def matches(cls, b: bytes) -> bool:
        truth_list = [
            b[0] == cls.OP_1[0],
            b[1] == cls.OP_PUSHBYTES_32[0],
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

    # ---- TESTING --- #


if __name__ == "__main__":
    sep = "---" * 80
    # P2TR testing
    test_xonly_pubkey = bytes.fromhex("a2fc329a085d8cfc4fa28795993d7b666cee024e94c40115141b8e9be4a29fa4")
    _scripts = [
        bytes.fromhex("5187"),
        bytes.fromhex("5287"),
        bytes.fromhex("5387"),
        bytes.fromhex("5487"),
        bytes.fromhex("5587")
    ]
    test_p2tr = P2TR_Key(xonly_pubkey=test_xonly_pubkey, scripts=_scripts)
    print(f"TEST P2TR FROM SCRIPTS: {test_p2tr.to_json()}")

    # # P2TR - Key Path
    # lmab_p2tr_bytes = bytes.fromhex("5120562529047f476b9a833a5a780a75845ec32980330d76d1ac9f351dc76bce5d72")
    # is_p2tr = P2TR_Key.matches(lmab_p2tr_bytes)
    # test_p2tr = P2TR_Key.from_bytes(lmab_p2tr_bytes)
    # print(f"LMAB P2TR: {test_p2tr.to_json()}")
    # print(f"MATCHES: {is_p2tr}")

    # # P2PK
    # lmab_p2pk_bytes = bytes.fromhex(
    #     "41049464205950188c29d377eebca6535e0f3699ce4069ecd77ffebfbd0bcf95e3c134cb7d2742d800a12df41413a09ef87a80516353a2f0a280547bb5512dc03da8ac")
    # is_p2pk = P2PK_Key.matches(lmab_p2pk_bytes)
    # test_p2pk = P2PK_Key.from_bytes(lmab_p2pk_bytes)
    # print(f"LMAB P2PK: {test_p2pk.to_json()}")
    # print(f"MATCHES: {is_p2pk}")
    # print(sep)
    #
    # # P2PKH
    # lmab_p2pkh_bytes = bytes.fromhex("76a91455ae51684c43435da751ac8d2173b2652eb6410588ac")
    # is_p2pkh = P2PKH_Key.matches(lmab_p2pkh_bytes)
    # test_p2pkh = P2PKH_Key.from_bytes(lmab_p2pkh_bytes)
    # print(f"LMAB P2PKH: {test_p2pkh.to_json()}")
    # print(f"MATCHES: {is_p2pkh}")
    #
    # # P2MS
    # lmab_p2ms_bytes = bytes.fromhex(
    #     "524104d81fd577272bbe73308c93009eec5dc9fc319fc1ee2e7066e17220a5d47a18314578be2faea34b9f1f8ca078f8621acd4bc22897b03daa422b9bf56646b342a24104ec3afff0b2b66e8152e9018fe3be3fc92b30bf886b3487a525997d00fd9da2d012dce5d5275854adc3106572a5d1e12d4211b228429f5a7b2f7ba92eb0475bb14104b49b496684b02855bc32f5daefa2e2e406db4418f3b86bca5195600951c7d918cdbe5e6d3736ec2abf2dd7610995c3086976b2c0c7b4e459d10b34a316d5a5e753ae")
    # is_p2ms = P2MS_Key.matches(lmab_p2ms_bytes)
    # test_p2ms = P2MS_Key.from_bytes(lmab_p2ms_bytes)
    # print(f"LMAB P2MS: {test_p2ms.to_json()}")
    # print(f"MATCHES: {is_p2ms}")
    #
    # # P2SH
    # lmab_p2sh_bytes = bytes.fromhex("a914748284390f9e263a4b766a75d0633c50426eb87587")
    # is_p2sh = P2SH_Key.matches(lmab_p2sh_bytes)
    # test_p2sh = P2SH_Key.from_bytes(lmab_p2sh_bytes)
    # print(f"LMAB P2SH: {test_p2sh.to_json()}")
    # print(f"MATCHES: {is_p2sh}")

    # P2WPKH
    # lmab_p2wpkh_bytes = bytes.fromhex("0014841b80d2cc75f5345c482af96294d04fdd66b2b7")
    # is_p2wpkh = P2WPKH_Key.matches(lmab_p2wpkh_bytes)
    # test_p2wpkh = P2WPKH_Key.from_bytes(lmab_p2wpkh_bytes)
    # print(f"LMAB P2WPKH: {test_p2wpkh.to_json()}")
    # print(f"MATCHES: {is_p2wpkh}")

    # lmab_p2wsh_bytes = bytes.fromhex("002065f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3")
    # is_p2wsh = P2WSH_Key.matches(lmab_p2wsh_bytes)
    # test_p2wsh = P2WSH_Key.from_bytes(lmab_p2wsh_bytes)
    # print(f"LMAB P2WSH: {test_p2wsh.to_json()}")
    # print(f"MATCHES: {is_p2wsh}")
