"""
HD Wallet
"""

import abc
from secrets import randbits
from typing import Union

from src.backup.crypto import sha256, pbkdf2, hmac_sha512, hash160, generator_exponent, ORDER, add_points
from src.backup.data import compress_public_key, decompress_public_key, encode_base58check, encode_bech32, \
    get_wordlist, \
    get_index_map, Keys, Wire
from src.backup.logger import get_logger

logger = get_logger(__name__)

_ntwk = Wire.Network


class Mnemonic:
    """
    A class for storing the mnemonic phrase used to generate the seed from which all extended keys are derived.
    """
    __slots__ = ("mnemonic",)

    def __init__(self, mnemonic: list | None = None, entropy: bytes | str | None = None,
                 entropy_bit_length: int = Keys.ENTROPY_BITS):

        # Check to see if a mnemonic is given
        if mnemonic is not None:
            if not self.validate_mnemonic(mnemonic):
                raise ValueError("Given mnemonic words do not pass validation")
            self.mnemonic = mnemonic

        # Generate new mnemonic otherwise
        else:
            # Check for entropy
            if entropy is not None:
                _entropy = self.parse_entropy(entropy, entropy_bit_length)
            # Generate random one
            else:
                _entropy = format(randbits(entropy_bit_length), f"0{entropy_bit_length}b")

            # Get checksum
            _checksum = self.get_entropy_checksum(_entropy)

            # Get mnemonic
            _seed_materials = _entropy + _checksum
            self.mnemonic = self.get_mnemonic_words(_seed_materials)

    @staticmethod
    def parse_entropy(input_entropy: bytes | str, entropy_bit_length: int):
        # Validate allowed entropy sizes per BIP-39
        if entropy_bit_length not in {128, 160, 192, 224, 256}:
            raise ValueError("entropy_bit_length must be one of 128,160,192,224,256")

        # Handle bytes
        if isinstance(input_entropy, bytes):
            entropy_num = int.from_bytes(input_entropy, byteorder="big")
        # Handle strings
        elif isinstance(input_entropy, str):
            # Hex
            if all(c in "0123456789abcdefABCDEF" for c in input_entropy):
                entropy_num = int(input_entropy, 16)
            # Binary
            elif all(c in "01" for c in input_entropy):
                entropy_num = int(input_entropy, 2)
            # Error
            else:
                raise ValueError("Inputted entropy not the correct datatype")
        else:
            raise ValueError("No entropy could be parsed")

        # Guard: never truncate silently; zero-pad to requested width
        if entropy_num.bit_length() > entropy_bit_length:
            raise ValueError("Input entropy has more bits than entropy_bit_length")
        return format(entropy_num, f"0{entropy_bit_length}b")

    @staticmethod
    def get_entropy_checksum(entropy):
        # Get entropy length
        bit_length = len(entropy) // 32

        # Hash entropy first
        entropy_hash = sha256(int(entropy, 2).to_bytes(len(entropy) // 8, byteorder="big"))

        # Get entropy_hash as binary string
        binary_entropy_hash = format(int.from_bytes(entropy_hash, byteorder="big"), f"0{Keys.ENTROPY_BITS}b")

        # Return first bit_length bits from the binary hash
        return binary_entropy_hash[:bit_length]

    @staticmethod
    def get_mnemonic_words(seed_materials: str):
        # Seed materials should be a binary string, with length divisible by 11
        if len(seed_materials) % 11 != 0 or not all(c in "01" for c in seed_materials):
            raise ValueError(f"Seed materials incorrectly formatted")

        # Break up binary string into chunks of length 11
        binary_chunks = [seed_materials[i:i + 11] for i in range(0, len(seed_materials), 11)]

        # Use binary chunks to get index from WORDLIST
        _wordlist = get_wordlist()
        return [_wordlist[int(c, 2)] for c in binary_chunks]

    def validate_mnemonic(self, word_list: list | None = None) -> bool:
        # Use instance mnemonic if none given
        _mnemonic = self.mnemonic if word_list is None else word_list

        # Convert words in the mnemonic back in to bits
        # index_list = [WORDLIST.index(w) for w in _mnemonic]
        idx_map = get_index_map()
        try:
            index_list = [idx_map[w] for w in _mnemonic]
        except KeyError:
            logger.error(f"Missing wordlist index in mnemonic:  {_mnemonic}")
            return False

        binary_string = "".join([format(i, f"011b") for i in index_list])

        # Get entropy and checksum part
        checksum_length = len(binary_string) // 33
        _entropy, _checksum = binary_string[:-checksum_length], binary_string[-checksum_length:]

        # Compute expected checksum from entropy
        expected_checksum = self.get_entropy_checksum(_entropy)

        # Return True if both checksums are equal, false otherwise
        return expected_checksum == _checksum

    def mnemonic_to_seed(self, passphrase: str = "") -> bytes:
        seed_bytes = pbkdf2(mnemonic=self.mnemonic, passphrase=passphrase)
        return seed_bytes


class ExtendedKey(abc.ABC):
    """
    Abstract base class for HD extended keys (xprv/xpub).
    Holds common BIP32 metadata: chain code, depth, parent fingerprint, child number, version bytes.
    """
    HARDENED_INDEX = 0x80000000

    __slots__ = ("chain_code", "depth", "parent_fingerprint", "child_number", "version")

    def __init__(
            self,
            chain_code: bytes,
            depth: int,
            parent_fingerprint: int,
            child_number: int,
            version: dict | None = None
    ):
        # -- Error checking -- #
        # - Chain code
        if not isinstance(chain_code, (bytes, bytearray)) or len(chain_code) != 32:
            raise ValueError("chain_code must be 32 bytes.")
        # - Depth
        if not (0 <= depth <= 255):
            raise ValueError("depth must be in [0,255].")
        # - Parent fingerprint
        if not (0 <= parent_fingerprint <= 0xFFFFFFFF):
            raise ValueError("parent_fingerprint must be a 4-byte unsigned int.")
        # - Child number
        if not (0 <= child_number <= 0xFFFFFFFF):
            raise ValueError("child_number must be a 4-byte unsigned int.")

        # -- Assign values -- #
        self.chain_code = chain_code
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.child_number = child_number
        self.version = version if version is not None else _ntwk.BIP44

    @abc.abstractmethod
    def derive_child(self, index: int) -> "ExtendedKey":
        """
        Derive a child key.
        Implementation differs for XPrv vs XPub.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def to_xpub(self) -> "XPub":
        """
        Return the public key version (if applicable).
        """
        raise NotImplementedError

    @abc.abstractmethod
    def fingerprint(self) -> int:
        """
        Returns the fingerprint of *this* key (first 4 bytes of HASH160(pubkey)).
        """
        raise NotImplementedError

    def _serialize_core(self, key_data_33: bytes, as_public=False) -> bytes:
        """
        Return the raw 78-byte serialization (BEFORE base58-check).
        key_data_33: the 33-byte portion of the key (0x00 + privkey, or full pubkey).
        """
        if len(key_data_33) != 33:
            raise ValueError("Key data must be 33 bytes. 0x00 + privkey or compressed pubkey.")

        ver = self.version["xpub" if as_public else "xprv"]

        raw = (
                ver +  # 4 bytes
                self.depth.to_bytes(1, 'big') +  # 1 byte
                self.parent_fingerprint.to_bytes(4, 'big') +  # 4 bytes
                self.child_number.to_bytes(4, 'big') +  # 4 bytes
                self.chain_code +  # 32 bytes
                key_data_33  # 33 bytes
        )
        return raw

    @abc.abstractmethod
    def address(self) -> str:
        """
        Return the base58-check serialization of the extended key (xprv/xpub).
        Must be overridden by XPrv / XPub because each must supply the correct key data (private vs. public).
        """
        raise NotImplementedError


class XPrv(ExtendedKey):
    """
    Extended Private Key (xprv).
    """
    SEED_KEY = b'Bitcoin seed'
    __slots__ = ("private_key",)

    def __init__(
            self,
            private_key: bytes,
            chain_code: bytes,
            depth: int,
            parent_fingerprint: int,
            child_number: int,
            version: dict | None = None
    ):
        # Call the parent init
        super().__init__(chain_code, depth, parent_fingerprint, child_number, version)

        # Error checking
        if not isinstance(private_key, (bytes, bytearray)) or len(private_key) != 32:
            raise ValueError("private_key must be 32 bytes.")

        # Assign vals
        self.private_key = bytes(private_key)

    @classmethod
    def from_master_seed(cls, seed: bytes, version: dict | None = None) -> "XPrv":
        """
        Create a master XPrv from a seed (BIP32).
        """
        # 1. Run the HMAC-SHA512
        # 2. Split the result into two 32-byte halves:
        hmac_hash = hmac_sha512(key=cls.SEED_KEY, message=seed)
        private_key, chain_code = hmac_hash[:32], hmac_hash[32:]

        # 3. Set master key parameters (depth=0, parent_fingerprint=0, child_number=0)
        depth = 0
        parent_fingerprint = 0
        child_number = 0

        # 4. Default version for xprv mainnet used in constructor of class
        # 5. Construct and return the ExtendedKey instance
        return cls(
            private_key=private_key,
            chain_code=chain_code,
            depth=depth,
            parent_fingerprint=parent_fingerprint,
            child_number=child_number,
            version=version
        )

    @classmethod
    def from_mnemonic(cls, mnemonic_obj: "Mnemonic", version: dict | None = None, passphrase: str = "") -> "XPrv":
        """
        Convenience classmethod to go directly from Mnemonic -> ExtendedKey.
        Calls mnemonic_to_seed() internally, then uses from_master_seed().
        """
        seed = mnemonic_obj.mnemonic_to_seed(passphrase)
        return cls.from_master_seed(seed, version)

    @property
    def is_hardened_child(self):
        return self.child_number >= self.HARDENED_INDEX

    def address(self) -> str:
        """
        Return the base58-check xprv string. The key data is (0x00 + private_key).
        """
        if len(self.private_key) != 32:
            raise ValueError("Private key must be 32 bytes.")

        # 33 bytes = 0x00 prefix + 32-byte private key
        key_data_33 = b'\x00' + self.private_key

        raw_78 = self._serialize_core(key_data_33)
        return encode_base58check(raw_78)

    def compressed_pubkey(self) -> bytes:
        """
        Return the compressed public key derived from the stored private key.
        """
        return compress_public_key(
            generator_exponent(int.from_bytes(self.private_key, "big"))
        )

    def to_xpub(self) -> "XPub":
        """
        Given an extended private key, we return the corresponding extended public key XPub
        """
        return XPub(
            public_key=self.compressed_pubkey(),
            chain_code=self.chain_code,
            depth=self.depth,
            parent_fingerprint=self.parent_fingerprint,
            child_number=self.child_number,
            version=self.version
        )

    def derive_child(self, index: int) -> "XPrv":
        """
        BIP32 child key derivation for an xprv.
        - If index >= 0x80000000 => hardened derivation, use private key in HMAC
        - Otherwise => normal derivation, use public key in HMAC
        Returns a new XPrv instance.
        """
        # 1. Determine if child is hardened or not
        hardened = True if index >= self.HARDENED_INDEX else False

        # 2. Format message data depending on index
        # Hardened -> 0x00 + priv_key + 4-byte index
        # Normal -> compressed_pubkey + 4-byte index
        data = (b"\x00" + self.private_key if hardened else self.compressed_pubkey()) + index.to_bytes(length=4,
                                                                                                       byteorder="big")
        # 3. Calculate HMAC(chain_code, data)
        hash_result = hmac_sha512(key=self.chain_code, message=data)

        # 4. Divide hash_result
        temp, new_chain_code = hash_result[:32], hash_result[32:]

        # 5. Get new private key as integer
        temp_int = int.from_bytes(temp, byteorder="big")
        privkey_int = int.from_bytes(self.private_key, byteorder="big")
        new_privkey_int = (privkey_int + temp_int) % ORDER

        # 6. Validate results
        if temp_int >= ORDER or new_privkey_int == 0:
            raise ValueError("Invalid child derivation.")

        # 7. Get new private key as bytes object
        new_privkey = new_privkey_int.to_bytes(length=32, byteorder="big")

        # 8. Return the new Xprv
        return XPrv(
            private_key=new_privkey,
            chain_code=new_chain_code,
            depth=self.depth + 1,
            parent_fingerprint=self.fingerprint(),
            child_number=index,
            version=self.version
        )

    def fingerprint(self) -> int:
        """
        Return the 4-byte (int) fingerprint of this key's compressed public key:
        the first 4 bytes of hash160(compressed_pubkey).
        """
        return int.from_bytes(hash160(self.compressed_pubkey())[:4], "big")

    def __repr__(self):
        return (
            f"<XPrv depth={self.depth} "
            f"fp={hex(self.parent_fingerprint)} "
            f"f={hex(self.fingerprint())} "
            f"child={self.child_number} "
            f"hardened_child={self.is_hardened_child} ...>"
        )


class XPub(ExtendedKey):
    """
    Extended Public Key (xpub).
    public_key is assumed to be the byte representation of the compressed public key
    """
    __slots__ = ("public_key",)

    def __init__(
            self,
            public_key: bytes,  # Compressed pubkey | 33 bytes
            chain_code: bytes,
            depth: int,
            parent_fingerprint: int,
            child_number: int,
            version: dict | None = None
    ):
        # Call the parent init
        super().__init__(chain_code, depth, parent_fingerprint, child_number, version)

        # Error checking
        if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 33:
            raise ValueError("public_key must be 33 bytes (compressed).")
        if public_key[0] not in (0x02, 0x03):
            raise ValueError("compressed public_key must start with 0x02 or 0x03.")

        # Assign value
        self.public_key = bytes(public_key)

    @property
    def public_key_point(self):
        return decompress_public_key(self.public_key)

    @property
    def pubkeyhash(self):
        return hash160(self.public_key)

    def derive_child(self, index: int) -> "XPub":
        """
        BIP32 child key derivation for an xpub (non-hardened only).
        If index >= 0x80000000, you can't derive that child from xpub (hardened).
        """
        # 1. Verify index
        if index >= XPrv.HARDENED_INDEX:
            raise ValueError("Cannot perform hardened derivation on an xpub")

        # 2. Format message data
        data = self.public_key + index.to_bytes(length=4, byteorder="big")

        # 3. Calculate HMAC(chain_code, data)
        hash_result = hmac_sha512(key=self.chain_code, message=data)

        # 4. Divide hash result
        temp, new_chain_code = hash_result[:32], hash_result[32:]

        # 5. Get new public key through elliptic curve pt addition
        temp_int = int.from_bytes(temp, byteorder="big")
        # Guard: Invalid index
        if temp_int >= ORDER or temp_int == 0:
            raise ValueError("Invalid child derivation.")
        temp_pt = generator_exponent(temp_int)
        new_pubkey_pt = add_points(self.public_key_point, temp_pt)

        # 6. Compress new public key
        new_public_key = compress_public_key(new_pubkey_pt)

        # 7. Return the new Xpub
        return XPub(
            public_key=new_public_key,
            chain_code=new_chain_code,
            depth=self.depth + 1,
            parent_fingerprint=self.fingerprint(),
            child_number=index,
            version=self.version
        )

    def to_xpub(self) -> "XPub":
        """
        Already an xpub, so just return self.
        """
        return self

    def fingerprint(self) -> int:
        """
        Return the 4-byte (int) fingerprint of this key's compressed public key:
        the first 4 bytes of hash160(compressed_pubkey).
        """
        return int.from_bytes(hash160(self.public_key)[:4], "big")

    def address(self) -> str:
        """
        Return the base58-check xpub string. The key data is compressed_pubkey.
        """
        if len(self.public_key) != 33:
            raise ValueError("Compressed public key must be 33 bytes.")

        raw_78 = self._serialize_core(self.public_key, as_public=True)
        return encode_base58check(raw_78)

    def __repr__(self):
        return (
            f"<XPub depth={self.depth} "
            f"fp={hex(self.parent_fingerprint)} "
            f"f={hex(self.fingerprint())} "
            f"child={self.child_number} ...>"
        )


class HDWallet:
    HARDENED_INDEX = 0x80000000
    BIP44_BASE_PATH = "m/44'/0'/0'/0/0"
    BIP49_BASE_PATH = "m/49'/0'/0'/0/0"
    BIP84_BASE_PATH = "m/84'/0'/0'/0/0"
    BIP86_BASE_PATH = "m/86'/0'/0'/0/0"
    MnemonicLike = Union[Mnemonic, list]

    __slots__ = ("mnemonic", "master_xprv", "cache", "hrp")

    def __init__(self, mnemonic: MnemonicLike = None, passphrase: str = "", version=None, hrp: str = _ntwk.HRP_MAIN):
        """
        We instantiate our wallet given a mnemonic phrase and optional passphrase. If no mnemonic is provided we
        create one.
        """
        # Get version
        if version is None:
            version = _ntwk.BIP44  # Default key byte dicts

        # Get mnemonic
        if mnemonic is None:
            self.mnemonic = Mnemonic()
        else:
            # Check obj
            if not (isinstance(mnemonic, Mnemonic) or isinstance(mnemonic, list)):
                raise ValueError("Given mnemonic of wrong type. Must be Mnemonic or list.")

            temp_mnemonic = Mnemonic(mnemonic) if isinstance(mnemonic, list) else mnemonic
            # Validate mnemonic
            if not temp_mnemonic.validate_mnemonic():
                raise ValueError(f"Given mnemonic {temp_mnemonic.mnemonic} does not pass validation")
            self.mnemonic = temp_mnemonic

        # Establish master key with passphrase
        self.master_xprv = XPrv.from_mnemonic(mnemonic_obj=self.mnemonic, passphrase=passphrase, version=version)

        # Cache dict for keys
        self.cache = {}

        # Bech32 HRP for SegWit addresses (mainnet 'bc', testnet 'tb')
        self.hrp = hrp

    def address(self, path: str, script_type: str = "p2pkh") -> str:
        """
        Generate an address for the given derivation path and script type.
        Supported: 'p2pkh', 'p2wpkh'. Others raise NotImplementedError.
        """
        # 1) Derive the key at the specified path (this returns an XPrv)
        derived_xprv = self.derive_key(path=path)

        # 2) Retrieve the compressed public key (33 bytes) from XPrv
        pubkey = derived_xprv.compressed_pubkey()

        # 4) Depending on script_type, compute the address
        match script_type.lower():
            case "p2pkh":
                return self._p2pkh_address(pubkey=pubkey)
            case "p2sh":
                # pay 2 script hash - have to know redeem script from script sig ahead of time
                raise NotImplementedError("P2SH address generation is not implemented yet.")
            case "p2wpkh":
                return self._p2wpkh_address(pubkey=pubkey)
            case "p2wsh":
                raise NotImplementedError("P2WSH address generation is not implemented yet.")
            case "p2tr":
                raise NotImplementedError("P2TR (Taproot) address generation is not implemented yet.")
            case _:
                raise ValueError(f"Unsupported script type: {script_type}")

    def _p2pkh_address(self, pubkey: bytes) -> str:
        """ Pay-to-PubKey-Hash: Base58Check(0x00 + hash160(pubkey)) """
        pubkeyhash = hash160(pubkey)
        return encode_base58check(b'\x00' + pubkeyhash)

    def _p2wpkh_address(self, pubkey: bytes) -> str:
        """Pay-to-WitnessField-PubKeyHash: Bech32(0x00 + hash160(pubkey))"""
        pubkeyhash = hash160(pubkey)
        return encode_bech32(pubkeyhash, hrp=self.hrp, witver=0)

    def derive_key(self, path: str, as_public=False):
        """
        Derive a key for the given path, e.g. m/44'/0'/0'/0/0
        - If as_public=True, return XPub
        - If as_public=False, return XPrv
        """
        if path in self.cache:
            # Already derived it
            cached = self.cache[path]  # always an XPrv
            return cached.to_xpub() if as_public else cached

        # parse path segments
        segments = path.split("/")
        if segments[0] not in ("m", ""):
            raise ValueError("Path must start with 'm'")

        # Start from master key
        current_key = self.master_xprv
        for seg in segments[1:]:
            hardened = seg.endswith("'")
            idx_str = seg.replace("'", "")
            idx = int(idx_str)
            if hardened:
                idx |= self.HARDENED_INDEX
            current_key = current_key.derive_child(idx)

        # Store only the private key in cache; return requested type
        self.cache[path] = current_key
        return current_key.to_xpub() if as_public else current_key

    def get_cached_paths(self):
        """Return all derivation paths we've derived so far."""
        return list(self.cache.keys())


if __name__ == "__main__":
    random_mnemonic = Mnemonic()
    random_wallet = HDWallet(mnemonic=random_mnemonic)
    test_path = "m/44'/0'/0'/0/0"

    # P2pkh
    test_p2pkh = random_wallet.address(path=test_path)
    print(f"TEST P2PKH: {test_p2pkh}")

    # P2PWKH
    test_p2wpkh = random_wallet.address(path=test_path, script_type="p2wpkh")
    print(f"TEST P2WPKH: {test_p2wpkh}")

    index_key = random_wallet.derive_key(path=random_wallet.BIP49_BASE_PATH)
    print(f"INDEX KEY: {index_key.address()}")

    # index_p2pkh
    test_index_p2pkh = random_wallet.address(path=random_wallet.BIP49_BASE_PATH, script_type="p2pkh")
    print(f"TEST INDEX P2PKH: {test_index_p2pkh}")

    # index_p2wpkh
    test_index_p2wpkh = random_wallet.address(path=random_wallet.BIP49_BASE_PATH, script_type="p2wpkh")
    print(f"TEST INDEX P2WPKH: {test_index_p2wpkh}")

    # # known_mnemonic = ['oak', 'recall', 'season', 'gain', 'awesome', 'master', 'advance', 'plate', 'paddle',
    # 'appear',
    # #                   'siege', 'provide', 'clinic', 'human', 'entire', 'taste', 'observe', 'taste', 'rotate',
    # 'trophy',
    # #                   'brick', 'reveal', 'course', 'flag']
    # # m1 = Mnemonic(mnemonic=known_mnemonic)
    # # w1 = HDWallet(mnemonic=m1, version=ExtendedKey.XPRV_BIP49)
    # # # key = w1.derive_key(path="m/44'/0'/0'/0/0")
    # # base_path = "m/49'/0'/0'/0/"
    # # for i in range(10):
    # #     temp_path = base_path + str(i)
    # #     temp_key = w1.derive_key(path=temp_path)
    # #     print(f"PATH: {temp_path}, KEY: {temp_key.address()}")
    # #
    # # temp_pubkey = bytes.fromhex("02e3af28965693b9ce1228f9d468149b831d6a0540b25e8a9900f71372c11fb277")
    # # temp_pubkeyhash = hash160(temp_pubkey)
    # # print(f"TEMP PUBKEYHASH: {temp_pubkeyhash.hex()}")
    #
    # # temp_xprv = XPrv(
    # #     private_key=bytes.fromhex("929120bea0c6b0f5557e3f6ff8d6e0cf060da29da38d71b9fcf5a830eab64ebe"),
    # #     chain_code=bytes.fromhex("464b1e32c316f91e64ccb014653c91883d0295d7a48ef9fa62786b1002361529"),
    # #     depth=4,
    # #     parent_fingerprint=int("d5777e8f", 16),
    # #     child_number=20,
    # #     version=ExtendedKey.XPRV_BIP84
    # # )
    # # print(f"CRAFTED KEY ADDRESS: {temp_xprv.address()}")
    #
    # # print(f"DERIVED KEY: {key.address()}")
    # # print(f"SEED: {m1.mnemonic_to_seed().hex()}")
    # # xprv = XPrv.from_mnemonic(mnemonic_obj=m1)
    # # print(f"XPRV MASTER: {xprv}")
    # # print(f"XPRV PRIVATE KEY: {xprv.private_key.hex()}")
    # # print(f"XPRV ADDRESS:{xprv.address()}")
    # #
    # # w1 = HDWallet(known_mnemonic)
    # # print(w1.master_xprv.address())
    #
    # # # xprv1 = xprv.derive_child(0)
    # # # print(f"XPRV INDEX 0 CHILD: {xprv1}")
    # # # xprv2 = xprv.derive_child(0x80000000)
    # # # print(f"XPRV FIRST HARDENED CHILD: {xprv2}")
    # # # xpub = xprv.to_public()
    # # # print(f"XPUB MASTER: {xpub}")
    # # # xpub1 = xpub.derive_child(0)
    # # # xpub2 = xpub.derive_child(1)
    # # # xpubn = xpub2.derive_child(5)
    # # # print(f"XPUB DERIVED CHILD INDEX 0: {xpub1}")
    # # # print(f"XPUB DERIVED CHILD INDEX 1: {xpub2}")
    # # # print(f"XPUB2 DERIVED CHILD INDEX 5: {xpubn}")
    # # # key_list = [xprv, xprv1, xprv2, xpub, xpub1, xpub2, xpubn]
    # # # for k in key_list:
    # # #     print(f"DERIVED PATH FOR {k.fingerprint()} : {k.d}")
    #
    # new_mnemonic_list = [
    #     "thrive", "quiz", "thing", "kit", "umbrella", "shock", "elevator", "expire", "century", "ketchup", "ill",
    #     "salute", "winter", "amused", "crop", "stairs", "spend", "submit", "below", "color", "cook", "concert",
    #     "lamp",
    #     "photo"]
    # new_mnemonic = Mnemonic(new_mnemonic_list)
    # print(f"BIP39 SEED: {new_mnemonic.mnemonic_to_seed().hex()}")
    #
    # test_wallet = HDWallet(mnemonic=new_mnemonic)
    # print(f"TEST WALLET ROOT KEY ADDRESS: {test_wallet.master_xprv.address()}")
    # print(f"TEST WALLET MASTER PRIVATE KEY: {test_wallet.master_xprv.private_key.hex()}")
    # print(f"TEST WALLET MASTER CHAIN CODE: {test_wallet.master_xprv.chain_code.hex()}")
    # print(f"TEST WALLET MASTER COMPRESSED PUBLIC KEY: {test_wallet.master_xprv.compressed_pubkey().hex()}")
    # # derived_xprv = test_wallet.derive_key(path="m/84'/0'/0'/0/0")
    # # account_xprv = test_wallet.derive_key(path="m/84'/0'/0")
    # # print(f"ACCOUNT XPRV ADDRESS: {account_xprv.address()}")
    # #
    # # # derived_xpub = test_wallet.derive_key(path="m/44'/0'/0'/0", as_public=True)
    # #
    # # print(f"DERIVED TYPE: {type(derived_xprv)}")
    # # test_xpub = derived_xprv.to_xpub()
    # #
    # # print(f"BIP32 DERIVED XPRV: {derived_xprv.address()}")
    # # print(f"BIP32 DERIVEED XPUB: {test_xpub.address()}")
    # # print(f"COMPRESSED PUBLIC KEY: {derived_xprv.to_xpub().public_key.hex()}")
    # #
    # # bip49_wallet = HDWallet(mnemonic=new_mnemonic)
