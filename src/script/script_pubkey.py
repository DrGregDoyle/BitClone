"""
The ScriptEngine class
"""
from dataclasses import dataclass
from typing import Optional

from src.crypto import secp256k1, sha256, hash160, tagged_hash_function, HashType
from src.data import encode_base58check, encode_bech32
from src.logger import get_logger
from src.script.script_engine import ScriptParser

logger = get_logger(__name__)


@dataclass
class ScriptPubKeyResult:
    scriptpubkey: bytes
    address: Optional[str]
    script_type: str


class ScriptPubKeyEngine:
    """
    A class used to create known ScriptPubKeys from a given private or public key
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

    def __init__(self):
        self.curve = secp256k1()
        self.parser = ScriptParser()

    # -- Helper Functions
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

    def _assemble_script(self, parts: list[bytes]) -> bytes:
        """
        Joins all script parts into a single bytes object.
        """
        return b''.join(parts)

    def _get_prefix(self, testnet: bool, pubkey_type: str) -> bytes:
        """
        Returns the version prefix byte for the given address type.
        """
        if pubkey_type == "p2pkh" or pubkey_type == "p2pk":
            return b'\x6f' if testnet else b'\x00'
        elif pubkey_type == "p2sh":
            return b'\xc4' if testnet else b'\x05'
        else:
            raise ValueError("Unknown address type for prefix")

    def _base58_address(self, payload: bytes, prefix: bytes) -> str:
        """
        Returns base58check encoded address.
        """
        return encode_base58check(prefix + payload)

    def _tweak_key(self, pubkey: bytes, merkle_root: bytes):
        """
        Returns tweaked pubkey based on given pubkey and merkle_root
        """
        x = int.from_bytes(pubkey, "big")
        y = self.curve.find_y_from_x(x)

        # Ensure even y
        if y % 2 != 0:
            y = self.curve.p - y

        # Verify (x,y)
        if not self.curve.is_point_on_curve((x, y)):
            raise ValueError("Public key point not on curve")

        # Calculate tweak
        tweak_data = pubkey + merkle_root
        tweak = tagged_hash_function(tweak_data, b"TapTweak", HashType.SHA256)
        tweak_int = int.from_bytes(tweak, "big")
        tweak_point = self.curve.multiply_generator(tweak_int)
        tweakedpubkey = self.curve.add_points(tweak_point, (x, y))
        return tweakedpubkey[0].to_bytes(32, "big")  # x-only

    # -- ScriptPubKeys

    def p2pk(self, pubkey: bytes, testnet: bool = False) -> ScriptPubKeyResult:
        """
        Pay to public key | OP_PUSHBYTES + pubkey + OP_CHECKSIG
        (The address is the corresponding P2PKH address).
        """
        pushbytes_op, _ = self._get_pubkey_info(pubkey)
        scriptpubkey = self._assemble_script([pushbytes_op, pubkey, self.OP_CHECKSIG])
        address = self._base58_address(hash160(pubkey), self._get_prefix(testnet, "p2pk"))
        return ScriptPubKeyResult(scriptpubkey=scriptpubkey, address=address, script_type='p2pk')

    def p2pkh(self, pubkey: bytes, testnet: bool = False) -> ScriptPubKeyResult:
        """
        Pay to Public Key Hash | OP_DUP + OP_HASH160 + OP_PUSHBYTES_20 + pubkeyhash + OP_EQUALVERIFY + OP_CHECKSIG
        """
        pubkeyhash = hash160(pubkey)
        scriptpubkey = self._assemble_script(
            [self.OP_DUP, self.OP_HASH160, self.OP_PUSHBYTES_20, pubkeyhash, self.OP_EQUALVERIFY, self.OP_CHECKSIG])
        address = self._base58_address(pubkeyhash, self._get_prefix(testnet, "p2pkh"))
        return ScriptPubKeyResult(scriptpubkey=scriptpubkey, address=address, script_type="p2pkh")

    def p2ms(self, key_list: list, signum: int = None) -> ScriptPubKeyResult:
        """
        Pay To MultiSig | OP_min OP_PUSHBYTES key1 OP_PUSHBYTES key2 ... OP_tot OP_CHECKMULTISIG

        OP_min = minimum number of signatures needed to unlock, OP_1 or greater
        OP_total = total number of signatures

        Uses multiple keys to lock bitcoins, and requires some (or all) of the signatures to unlock it.
        P2MS has no address format
        """
        _total = len(key_list)  # Number of pubkeys
        _min = signum if signum is not None else _total

        if not (1 <= _min <= _total <= 16):
            raise ValueError("Invalid number of keys or required signatures")

        # Get op_min and op_total as byte code
        op_min = bytes.fromhex(hex(0x50 + _min)[2:])
        op_total = bytes.fromhex(hex(0x50 + _total)[2:])

        # Get list of op_codes | Start with op_min
        script_parts = [op_min]

        # Pushbytes and key for each key
        for pubkey in key_list:
            push_code, _ = self._get_pubkey_info(pubkey)
            script_parts.extend([push_code, pubkey])

        # Total number and OP_CHECKMULTISIG
        script_parts.extend([op_total, self.OP_CHECKMULTISIG])

        return ScriptPubKeyResult(
            scriptpubkey=self._assemble_script(script_parts),
            address=None,
            script_type="p2ms"
        )

    def p2sh(self, script: bytes, testnet: bool = False) -> ScriptPubKeyResult:
        """
        Pay to Script Hash | OP_HASH160 + scripthash + OP_EQUAL
        Given the provided script, we hash160 it and return the corresponding scriptpubkey
        """
        scripthash = hash160(script)
        scriptpubkey = self._assemble_script([self.OP_HASH160, scripthash, self.OP_EQUAL])
        address = self._base58_address(scripthash, self._get_prefix(testnet, "p2sh"))
        return ScriptPubKeyResult(scriptpubkey=scriptpubkey, address=address, script_type="p2sh")

    def p2wpkh(self, pubkey: bytes, testnet: bool = False) -> ScriptPubKeyResult:
        """
        Pay to Witness Public Key Hash | OP_0 + OP_PUSHBYTES_20 + pubkeyhash
        Works similarly to a p2pkh but is unlocked via the Witness field
        """
        # Hash
        if len(pubkey) != 33:
            raise ValueError("Given public key is not correct compressed public key size")
        pubkeyhash = hash160(pubkey)

        scriptpubkey = self._assemble_script([self.OP_0, self.OP_PUSHBYTES_20, pubkeyhash])
        address = encode_bech32(pubkeyhash)
        return ScriptPubKeyResult(scriptpubkey=scriptpubkey, address=address, script_type="p2wpkh")

    def p2wsh(self, script: bytes, testnet: bool = False) -> ScriptPubKeyResult:
        """
        Pay to Witness Script Hash (P2WSH) | OP_0 + OP_PUSHBYTES_32 + scripthash
        Accepts a full redeem script and returns a P2WSH scriptPubKey and address.
        """
        scripthash = sha256(script)
        scriptpubkey = self._assemble_script([self.OP_0, self.OP_PUSHBYTES_20, scripthash])

        # Address: bech32 with witness version 0
        hrp = "tb" if testnet else "bc"
        address = encode_bech32(scripthash, witver=0, hrp=hrp)

        return ScriptPubKeyResult(scriptpubkey=scriptpubkey, address=address, script_type="p2wsh")

    def p2tr(self, pubkey: bytes, merkle_root: bytes, testnet: bool = False) -> ScriptPubKeyResult:
        """
        Pay to Taproot (P2TR) | OP_1 + OP_PUSHBYTES_32 + taproot
        Accepts a 32-byte x-only public key (already tweaked).
        """
        if len(pubkey) != 32:
            raise ValueError("Taproot public key must be exactly 32 bytes (x-only format)")

        taproot = self._tweak_key(pubkey, merkle_root)
        scriptpubkey = self._assemble_script([self.OP_1, self.OP_PUSHBYTES_32, taproot])

        # Address encoding with Bech32m
        hrp = 'tb' if testnet else 'bc'
        address = encode_bech32(taproot, hrp, witver=1)

        return ScriptPubKeyResult(scriptpubkey=scriptpubkey, address=address, script_type="p2tr")


# --- TESTING

if __name__ == "__main__":
    pass
