"""
The ScriptPubKey class that provides factory methods for different script types.
"""
from enum import Enum

from src.crypto import secp256k1, hash160
from src.data import encode_base58check
from src.logger import get_logger
from src.script.script_parser import ScriptParser

logger = get_logger(__name__)


class ScriptType(Enum):
    P2PK = "P2PK"
    P2PKH = "P2PKH"
    P2MS = "P2MS"
    P2SH = "P2SH"
    P2WPKH = "P2WPKH"
    P2WSH = "P2WSH"
    P2TR = "P2TR"


class ScriptPubKey:
    """
    A class representing scriptPubKey with factory methods to create different types
    """
    # -- Common OP-Codes
    OP_0 = b'\x00'
    OP_PUSHBYTES_20 = b'\x14'
    OP_PUSHBYTES_32 = b'\x20'
    OP_PUSHBYTES_33 = b'\x21'
    OP_PUSHBYTES_65 = b'\x41'
    OP_1 = b'\x51'
    OP_DUP = b'\x76'
    OP_EQUAL = b'\x87'
    OP_EQUALVERIFY = b'\x88'
    OP_HASH160 = b'\xa9'
    OP_CHECKSIG = b'\xac'
    OP_CHECKMULTISIG = b'\xae'

    def __init__(self, script_type: ScriptType, *args, testnet: bool = False):
        self.script_type = script_type
        self.testnet = testnet
        self._parser = ScriptParser()

        # Map script types to their handler functions
        handlers = {
            ScriptType.P2PK: self._handle_p2pk,
            ScriptType.P2PKH: self._handle_p2pkh,
            ScriptType.P2MS: self._handle_p2ms,
            # ScriptType.P2SH: self._handle_p2sh,
            # ScriptType.P2WPKH: self._handle_p2wpkh,
            # ScriptType.P2WSH: self._handle_p2wsh,
            # ScriptType.P2TR: self._handle_p2tr,
        }

        handler = handlers.get(self.script_type)

        if handler is None:
            raise ValueError(f"Unsupported script type: {self.script_type}")

        # Safely call the handler
        self.script, self.address = handler(*args)
        self.asm = self._parser.parse_script(self.script)

    # --- HELPERS

    def _get_prefix(self) -> bytes:
        """
        Returns the version prefix byte for the given address type.
        """
        if self.script_type == ScriptType.P2PK or self.script_type == ScriptType.P2PKH:
            return b'\x6f' if self.testnet else b'\x00'
        elif self.script_type == ScriptType.P2SH:
            return b'\xc4' if self.testnet else b'\x05'
        else:
            raise ValueError("Unknown address type for prefix")

    def _get_pubkey_info(self, pubkey: bytes) -> tuple[bytes, bool]:
        """
        Returns the appropriate push opcode and compression flag for a given pubkey.
        """
        if len(pubkey) == 33:
            return self.OP_PUSHBYTES_33, True
        elif len(pubkey) == 65:
            return self.OP_PUSHBYTES_65, False
        else:
            raise ValueError("Invalid public key length")

    def _base58_address(self, payload: bytes, prefix: bytes) -> str:
        """
        Returns base58check encoded address.
        """
        return encode_base58check(prefix + payload)

    # --- HANDLERS
    def _handle_p2pk(self, pubkey: bytes):
        """
        P2PK | OP_PUSHBYTES_ + pubkey + OP_CHECKSIG
        """
        # Validate pubkey
        pubkey_len = len(pubkey)
        if pubkey_len != 33 and pubkey_len != 65:
            raise ValueError(f"Pubkey not in correct format. Length: {pubkey_len}, expected 33 or 65 bytes")

        p2pk_address = self._base58_address(hash160(pubkey), self._get_prefix())

        # Assemble script
        push_op = self.OP_PUSHBYTES_65 if pubkey_len == 65 else self.OP_PUSHBYTES_33
        return (push_op + pubkey + self.OP_CHECKSIG), p2pk_address

    def _handle_p2pkh(self, pubkey: bytes):
        """
        P2PKH | OP_DUP + OP_HASH160 + OP_PUSHBYTES_20 + pubkeyhash + OP_EQUALVERIFY + OP_CHECKSIG
        """
        # Script
        pubkeyhash = hash160(pubkey)
        script = self.OP_DUP + self.OP_HASH160 + self.OP_PUSHBYTES_20 + pubkeyhash + self.OP_EQUALVERIFY + \
                 self.OP_CHECKSIG

        # address
        p2pkh_address = self._base58_address(pubkeyhash, self._get_prefix())
        return script, p2pkh_address

    def _handle_p2ms(self, keylist: list, signum: int):
        """
        Pay To MultiSig | OP_min OP_PUSHBYTES key1 OP_PUSHBYTES key2 ... OP_tot OP_CHECKMULTISIG

        OP_min = minimum number of signatures needed to unlock, OP_1 or greater
        OP_total = total number of signatures

        Uses multiple keys to lock bitcoins, and requires some (or all) of the signatures to unlock it.
        P2MS has no address format
        """
        _total = len(keylist)  # Number of pubkeys
        _min = signum if signum is not None else _total

        if not (1 <= _min <= _total <= 16):
            raise ValueError("Invalid number of keys or required signatures")

        # Get op_min and op_total as byte code
        op_min = bytes.fromhex(hex(0x50 + _min)[2:])
        op_total = bytes.fromhex(hex(0x50 + _total)[2:])

        # Get list of op_codes | Start with op_min
        script_parts = [op_min]

        # Pushbytes and key for each key
        for pubkey in keylist:
            push_code, _ = self._get_pubkey_info(pubkey)
            script_parts.extend([push_code, pubkey])

        # Total number and OP_CHECKMULTISIG
        script_parts.extend([op_total, self.OP_CHECKMULTISIG])

        script = b''.join(script_parts)
        return script, None  # No address for P2MS

    # @staticmethod
    # def _get_pubkey_info(pubkey: bytes) -> Tuple[bytes, bool]:
    #     """
    #     Returns the appropriate push opcode and compression flag for a given pubkey.
    #     """
    #     if len(pubkey) == 33:
    #         return ScriptPubKey.OP_PUSHBYTES_33, True
    #     elif len(pubkey) == 65:
    #         return ScriptPubKey.OP_PUSHBYTES_65, False
    #     else:
    #         raise ValueError("Invalid public key length")
    #
    # @staticmethod
    # def _assemble_script(parts: list[bytes]) -> bytes:
    #     """
    #     Joins all script parts into a single bytes object.
    #     """
    #     return b''.join(parts)
    #
    # @staticmethod
    # def _get_prefix(testnet: bool, pubkey_type: str) -> bytes:
    #     """
    #     Returns the version prefix byte for the given address type.
    #     """
    #     if pubkey_type == "p2pkh" or pubkey_type == "p2pk":
    #         return b'\x6f' if testnet else b'\x00'

    #     elif pubkey_type == "p2sh":
    #         return b'\xc4' if testnet else b'\x05'
    #     else:
    #         raise ValueError("Unknown address type for prefix")
    #
    # @staticmethod
    # def _base58_address(payload: bytes, prefix: bytes) -> str:
    #     """
    #     Returns base58check encoded address.
    #     """
    #     return encode_base58check(prefix + payload)
    #
    # @staticmethod
    # def _tweak_key(pubkey: bytes, merkle_root: bytes):
    #     """
    #     Returns tweaked pubkey based on given pubkey and merkle_root
    #     """
    #     curve = secp256k1()
    #     x = int.from_bytes(pubkey, "big")
    #     y = curve.find_y_from_x(x)
    #
    #     # Ensure even y
    #     if y % 2 != 0:
    #         y = curve.p - y
    #
    #     # Verify (x,y)
    #     if not curve.is_point_on_curve((x, y)):
    #         raise ValueError("Public key point not on curve")
    #
    #     # Calculate tweak
    #     tweak_data = pubkey + merkle_root
    #     tweak = tagged_hash_function(tweak_data, b"TapTweak", HashType.SHA256)
    #     tweak_int = int.from_bytes(tweak, "big")
    #     tweak_point = curve.multiply_generator(tweak_int)
    #     tweakedpubkey = curve.add_points(tweak_point, (x, y))
    #     return tweakedpubkey[0].to_bytes(32, "big")  # x-only
    #
    # # @classmethod
    # # def from_result(cls, result: ScriptPubKeyResult, testnet: bool = False) -> 'ScriptPubKey':
    # #     """
    # #     Create a ScriptPubKey object from a ScriptPubKeyResult.
    # #     """
    # #     return cls(
    # #         script=result.scriptpubkey,
    # #         script_type=result.script_type,
    # #         address=result.address,
    # #         testnet=testnet
    # #     )
    #
    # @classmethod
    # def p2pk(cls, pubkey: bytes, testnet: bool = False) -> 'ScriptPubKey':
    #     """
    #     Pay to public key | OP_PUSHBYTES + pubkey + OP_CHECKSIG
    #     (The address is the corresponding P2PKH address).
    #     """
    #     pushbytes_op, _ = cls._get_pubkey_info(pubkey)
    #     scriptpubkey = cls._assemble_script([pushbytes_op, pubkey, cls.OP_CHECKSIG])
    #     address = cls._base58_address(hash160(pubkey), cls._get_prefix(testnet, "p2pk"))
    #
    #     return cls.from_result(result, testnet)
    #
    # @classmethod
    # def p2pkh(cls, pubkey: bytes, testnet: bool = False) -> 'ScriptPubKey':
    #     """
    #     Pay to Public Key Hash | OP_DUP + OP_HASH160 + OP_PUSHBYTES_20 + pubkeyhash + OP_EQUALVERIFY + OP_CHECKSIG
    #     """
    #     pubkeyhash = hash160(pubkey)
    #     scriptpubkey = cls._assemble_script(
    #         [cls.OP_DUP, cls.OP_HASH160, cls.OP_PUSHBYTES_20, pubkeyhash, cls.OP_EQUALVERIFY, cls.OP_CHECKSIG]
    #     )
    #     address = cls._base58_address(pubkeyhash, cls._get_prefix(testnet, "p2pkh"))
    #
    #     result = ScriptPubKeyResult(
    #         scriptpubkey=scriptpubkey,
    #         address=address,
    #         script_type="p2pkh"
    #     )
    #
    #     return cls.from_result(result, testnet)
    #
    # @classmethod
    # def p2ms(cls, key_list: List[bytes], signum: int = None, testnet: bool = False) -> 'ScriptPubKey':
    #     """
    #     Pay To MultiSig | OP_min OP_PUSHBYTES key1 OP_PUSHBYTES key2 ... OP_tot OP_CHECKMULTISIG
    #
    #     OP_min = minimum number of signatures needed to unlock, OP_1 or greater
    #     OP_total = total number of signatures
    #
    #     Uses multiple keys to lock bitcoins, and requires some (or all) of the signatures to unlock it.
    #     P2MS has no address format
    #     """
    #     _total = len(key_list)  # Number of pubkeys
    #     _min = signum if signum is not None else _total
    #
    #     if not (1 <= _min <= _total <= 16):
    #         raise ValueError("Invalid number of keys or required signatures")
    #
    #     # Get op_min and op_total as byte code
    #     op_min = bytes.fromhex(hex(0x50 + _min)[2:])
    #     op_total = bytes.fromhex(hex(0x50 + _total)[2:])
    #
    #     # Get list of op_codes | Start with op_min
    #     script_parts = [op_min]
    #
    #     # Pushbytes and key for each key
    #     for pubkey in key_list:
    #         push_code, _ = cls._get_pubkey_info(pubkey)
    #         script_parts.extend([push_code, pubkey])
    #
    #     # Total number and OP_CHECKMULTISIG
    #     script_parts.extend([op_total, cls.OP_CHECKMULTISIG])
    #
    #     result = ScriptPubKeyResult(
    #         scriptpubkey=cls._assemble_script(script_parts),
    #         address=None,
    #         script_type="p2ms"
    #     )
    #
    #     return cls.from_result(result, testnet)
    #
    # @classmethod
    # def p2sh(cls, script: bytes, testnet: bool = False) -> 'ScriptPubKey':
    #     """
    #     Pay to Script Hash | OP_HASH160 + scripthash + OP_EQUAL
    #     Given the provided script, we hash160 it and return the corresponding scriptpubkey
    #     """
    #     scripthash = hash160(script)
    #     scriptpubkey = cls._assemble_script([cls.OP_HASH160, cls.OP_PUSHBYTES_20, scripthash, cls.OP_EQUAL])
    #     address = cls._base58_address(scripthash, cls._get_prefix(testnet, "p2sh"))
    #
    #     result = ScriptPubKeyResult(
    #         scriptpubkey=scriptpubkey,
    #         address=address,
    #         script_type="p2sh"
    #     )
    #
    #     return cls.from_result(result, testnet)
    #
    # @classmethod
    # def p2wpkh(cls, pubkey: bytes, testnet: bool = False) -> 'ScriptPubKey':
    #     """
    #     Pay to Witness Public Key Hash | OP_0 + OP_PUSHBYTES_20 + pubkeyhash
    #     Works similarly to a p2pkh but is unlocked via the Witness field
    #     """
    #     # Hash
    #     if len(pubkey) != 33:
    #         raise ValueError("Given public key is not correct compressed public key size")
    #     pubkeyhash = hash160(pubkey)
    #
    #     scriptpubkey = cls._assemble_script([cls.OP_0, cls.OP_PUSHBYTES_20, pubkeyhash])
    #     address = encode_bech32(pubkeyhash)
    #
    #     result = ScriptPubKeyResult(
    #         scriptpubkey=scriptpubkey,
    #         address=address,
    #         script_type="p2wpkh"
    #     )
    #
    #     return cls.from_result(result, testnet)
    #
    # @classmethod
    # def p2wsh(cls, script: bytes, testnet: bool = False) -> 'ScriptPubKey':
    #     """
    #     Pay to Witness Script Hash (P2WSH) | OP_0 + OP_PUSHBYTES_32 + scripthash
    #     Accepts a full redeem script and returns a P2WSH scriptPubKey and address.
    #     """
    #     scripthash = sha256(script)
    #     scriptpubkey = cls._assemble_script([cls.OP_0, cls.OP_PUSHBYTES_32, scripthash])
    #
    #     # Address: bech32 with witness version 0
    #     hrp = "tb" if testnet else "bc"
    #     address = encode_bech32(scripthash, witver=0, hrp=hrp)
    #
    #     result = ScriptPubKeyResult(
    #         scriptpubkey=scriptpubkey,
    #         address=address,
    #         script_type="p2wsh"
    #     )
    #
    #     return cls.from_result(result, testnet)
    #
    # @classmethod
    # def p2tr(cls, pubkey: bytes, merkle_root: bytes, testnet: bool = False) -> 'ScriptPubKey':
    #     """
    #     Pay to Taproot (P2TR) | OP_1 + OP_PUSHBYTES_32 + taproot
    #     Accepts a 32-byte x-only public key (already tweaked).
    #     """
    #     if len(pubkey) != 32:
    #         raise ValueError("Taproot public key must be exactly 32 bytes (x-only format)")
    #
    #     taproot = cls._tweak_key(pubkey, merkle_root)
    #     scriptpubkey = cls._assemble_script([cls.OP_1, cls.OP_PUSHBYTES_32, taproot])
    #
    #     # Address encoding with Bech32m
    #     hrp = 'tb' if testnet else 'bc'
    #     address = encode_bech32(taproot, hrp, witver=1)
    #
    #     result = ScriptPubKeyResult(
    #         scriptpubkey=scriptpubkey,
    #         address=address,
    #         script_type="p2tr"
    #     )
    #
    #     return cls.from_result(result, testnet)
    #
    def to_dict(self):
        """
        Returns human-readable dict of the values
        """
        spk_dict = {
            "script_type": self.script_type.value,
            "script": self.script.hex(),
            "address": self.address,
            "asm": self.asm,
            "testnet": self.testnet
        }
        return spk_dict

    def to_json(self):
        """
        Returns a JSON string representation of this ScriptPubKey
        """
        import json
        return json.dumps(self.to_dict(), indent=2)


# --- TESTING
if __name__ == "__main__":
    from secrets import randbits
    from src.data import compress_public_key

    # Example: Generate P2PK script
    curve = secp256k1()
    priv_key = randbits(256) % curve.p
    pk_pt = curve.multiply_generator(priv_key)
    _pubkey = compress_public_key(pk_pt)

    # Create P2PK script using the factory method
    p2pk_script = ScriptPubKey(ScriptType.P2PK, _pubkey)
    print(p2pk_script.to_json())

    # Create P2PKH script
    p2pkh_script = ScriptPubKey(ScriptType.P2PKH, _pubkey)
    print(p2pkh_script.to_json())
