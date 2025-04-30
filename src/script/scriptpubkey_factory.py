"""
The ScriptPubKey class that provides factory methods for different script types.
"""
from enum import Enum

from src.crypto import secp256k1, sha256, hash160, tagged_hash_function, HashType
from src.data import encode_base58check, encode_bech32
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
    CUSTOM = "CUSTOM"


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
        # Internals
        self._parser = ScriptParser()
        self.curve = secp256k1()

        self.script_type = script_type
        self.testnet = testnet

        # Map script types to their handler functions
        handlers = {
            ScriptType.P2PK: self._handle_p2pk,
            ScriptType.P2PKH: self._handle_p2pkh,
            ScriptType.P2MS: self._handle_p2ms,
            ScriptType.P2SH: self._handle_p2sh,
            ScriptType.P2WPKH: self._handle_p2wpkh,
            ScriptType.P2WSH: self._handle_p2wsh,
            ScriptType.P2TR: self._handle_p2tr
        }

        handler = handlers.get(self.script_type)

        if handler is None:
            raise ValueError(f"Unsupported script type: {self.script_type}")

        # Safely call the handler
        self.script, self.address = handler(*args)
        self.asm = self._parser.parse_script(self.script)

    # --- CUSTOM
    @classmethod
    def from_script(cls, script: bytes, testnet: bool = False) -> "ScriptPubKey":
        obj = cls.__new__(cls)
        obj.script_type = cls.detect_type_from_script(script)
        if obj.script_type == ScriptType.CUSTOM:
            obj.testnet = testnet
            obj.script = script
            obj._parser = ScriptParser()
            obj.address = ""  # or attempt to detect one if possible
            obj.asm = obj._parser.parse_script(script)
            return obj
        else:
            return cls(obj.script_type, script)

    # --- HELPERS
    def detect_type_from_script(self, script: bytes) -> ScriptType | None:
        """
        Attempts to classify a raw script into a known ScriptType.
        Returns ScriptType or None if detection fails.
        """
        # P2PKH
        if (len(script) == 25 and
                script[0] == self.OP_DUP[0] and
                script[1] == self.OP_HASH160[0] and
                script[2] == self.OP_PUSHBYTES_20[0] and
                script[-2] == self.OP_EQUALVERIFY[0] and
                script[-1] == self.OP_CHECKSIG[0]):
            return ScriptType.P2PKH

        # P2SH
        if (len(script) == 23 and
                script[0] == self.OP_HASH160[0] and
                script[1] == self.OP_PUSHBYTES_20[0] and
                script[-1] == self.OP_EQUAL[0]):
            return ScriptType.P2SH

        # P2WPKH
        if (len(script) == 22 and
                script[0] == self.OP_0[0] and
                script[1] == self.OP_PUSHBYTES_20[0]):
            return ScriptType.P2WPKH

        # P2WSH
        if (len(script) == 34 and
                script[0] == self.OP_0[0] and
                script[1] == self.OP_PUSHBYTES_32[0]):
            return ScriptType.P2WSH

        # P2TR
        if (len(script) == 34 and
                script[0] == self.OP_1[0] and
                script[1] == self.OP_PUSHBYTES_32[0]):
            return ScriptType.P2TR

        # P2PK
        if script[-1:] == self.OP_CHECKSIG:
            pubkey_len = len(script[1:-1])
            op_code = script[0]
            if op_code == pubkey_len:
                return ScriptType.P2PK

        # Custom
        return ScriptType.CUSTOM

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

    def _base58_address(self, payload: bytes) -> str:
        """
        Returns base58check encoded address.
        """
        prefix = self._get_prefix()
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

    # --- HANDLERS
    def _handle_p2pk(self, pubkey: bytes):
        """
        P2PK | OP_PUSHBYTES_ + pubkey + OP_CHECKSIG
        """
        # Validate pubkey
        pubkey_len = len(pubkey)
        if pubkey_len != 33 and pubkey_len != 65:
            raise ValueError(f"Pubkey not in correct format. Length: {pubkey_len}, expected 33 or 65 bytes")

        # Assemble script
        push_op = self.OP_PUSHBYTES_65 if pubkey_len == 65 else self.OP_PUSHBYTES_33
        p2pk_script = push_op + pubkey + self.OP_CHECKSIG

        # Address
        p2pk_address = self._base58_address(hash160(pubkey))

        return p2pk_script, p2pk_address

    def _handle_p2pkh(self, pubkey: bytes):
        """
        P2PKH | OP_DUP + OP_HASH160 + OP_PUSHBYTES_20 + pubkeyhash + OP_EQUALVERIFY + OP_CHECKSIG
        """
        # Script
        pubkeyhash = hash160(pubkey)
        p2pkh_script = self.OP_DUP + self.OP_HASH160 + self.OP_PUSHBYTES_20 + pubkeyhash + self.OP_EQUALVERIFY + \
                       self.OP_CHECKSIG

        # address
        p2pkh_address = self._base58_address(pubkeyhash)
        return p2pkh_script, p2pkh_address

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

    def _handle_p2sh(self, redeem_script: bytes):
        """
        P2SH | OP_HASH160 + OP_PUSHBYTES_20 + scripthash + OP_EQUAL
        Given the provided script, we hash160 it and return the corresponding scriptpubkey
        """
        scripthash = hash160(redeem_script)
        p2sh_script = self.OP_HASH160 + self.OP_PUSHBYTES_20 + scripthash + self.OP_EQUAL
        p2sh_address = self._base58_address(scripthash)
        return p2sh_script, p2sh_address

    def _handle_p2wpkh(self, pubkey: bytes):
        """
        P2WPKH | OP_0 + OP_PUSHBYTES_20 + pubkeyhash
        Works similarly to a p2pkh but is unlocked via the Witness field
        """
        # Hash
        if len(pubkey) != 33:
            raise ValueError("Given public key is not correct compressed public key size")
        pubkeyhash = hash160(pubkey)
        p2wpkh_script = self.OP_0 + self.OP_PUSHBYTES_20 + pubkeyhash
        p2wpkh_address = encode_bech32(pubkeyhash)

        return p2wpkh_script, p2wpkh_address

    def _handle_p2wsh(self, redeem_script: bytes):
        """
        P2WSH | OP_0 + OP_PUSHBYTES_32 + scripthash
        Accepts a full redeem script and returns a P2WSH scriptPubKey and address.
        """
        scripthash = sha256(redeem_script)
        p2wsh_script = self.OP_0 + self.OP_PUSHBYTES_32 + scripthash

        # Address: bech32 with witness version 0
        hrp = "tb" if self.testnet else "bc"
        p2wsh_address = encode_bech32(scripthash, witver=0, hrp=hrp)

        return p2wsh_script, p2wsh_address

    def _handle_p2tr(self, pubkey: bytes, merkle_root: bytes):
        """
        P2TR | OP_1 + OP_PUSHBYTES_32 + taproot
        Accepts a 32-byte x-only public key (already tweaked).
        """
        if len(pubkey) != 32:
            raise ValueError("Taproot public key must be exactly 32 bytes (x-only format)")

        taproot = self._tweak_key(pubkey, merkle_root)
        p2tr_script = self.OP_1 + self.OP_PUSHBYTES_32 + taproot

        # Address encoding with Bech32m
        hrp = 'tb' if self.testnet else 'bc'
        p2tr_address = encode_bech32(taproot, hrp, witver=1)

        return p2tr_script, p2tr_address

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
    _p2pk_script = ScriptPubKey(ScriptType.P2PK, _pubkey)
    print(_p2pk_script.to_json())

    # Create P2PKH script
    _p2pkh_script = ScriptPubKey(ScriptType.P2PKH, _pubkey)
    print(_p2pkh_script.to_json())
