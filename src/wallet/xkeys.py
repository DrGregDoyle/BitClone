"""
Extended Keys (xpub/xprv) Implementation for BitClone Wallet
Implements BIP32 Hierarchical Deterministic Wallet key derivation

"""
import json
from io import BytesIO

from src.core import ExtendedKeyError, XKEYS, get_stream, read_stream
from src.cryptography import SECP256K1, hash160, hmac_sha512, hash256
from src.data import encode_base58, decode_base58

__all__ = ["ExtendedKey"]

from src.data.ecc_keys import PubKey

BIP44_XPRV = XKEYS.BIP44_XPRV
BIP44_XPUB = XKEYS.BIP44_XPUB
BIP49_XPRV = XKEYS.BIP49_XPRV
BIP49_XPUB = XKEYS.BIP49_XPUB
BIP84_XPRV = XKEYS.BIP84_XPRV
BIP84_XPUB = XKEYS.BIP84_XPUB
TESTNET_PRV = XKEYS.TESTNET_PRIVATE
TESTNET_PUB = XKEYS.TESTNET_PUBLIC
HARDENED_INDEX = XKEYS.HARDENED_OFFSET
SEED_KEY = XKEYS.SEED_KEY

VERSIONS = [BIP44_XPRV, BIP44_XPUB, BIP49_XPRV, BIP84_XPRV, BIP84_XPUB, TESTNET_PRV, TESTNET_PUB]


class ExtendedKey:
    """
    Base class for extended keys (xpub/xprv)
    Implements BIP32 hierarchical deterministic key derivation
    """
    __slots__ = ('version', 'depth', 'parent_fingerprint', 'child_number', 'chain_code', 'key_data')

    def __init__(self,
                 key_data: bytes,
                 chain_code: bytes,
                 depth: int,
                 parent_fingerprint: bytes,
                 child_number: int,
                 version: bytes,
                 ):
        """
        Initialize extended key

        Args:
            key_data: Key data (32 bytes for private, 33 bytes for public)
            chain_code: Chain code for key derivation (32 bytes)
            depth: Depth in the derivation path
            parent_fingerprint: Fingerprint of parent key (4 bytes)
            child_number: Child key index
            version: Version bytes (determines key type and network)
        """
        # --- Validation --- #
        if len(parent_fingerprint) != 4:
            raise ExtendedKeyError("Parent fingerprint must be 4 bytes")
        if len(chain_code) != 32:
            raise ExtendedKeyError("Chain code must be 32 bytes")

        # --- Get Keys

        self.version = version
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.child_number = child_number
        self.chain_code = chain_code
        self.key_data = key_data

    # --- OVERRIDES --- #
    # Add these methods to your ExtendedKey class

    def __eq__(self, other) -> bool:
        """
        Two ExtendedKey objects are equal if and only if their serialized bytes are equal
        """
        if not isinstance(other, ExtendedKey):
            return False

        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        """
        Hash based on the serialized bytes to maintain consistency with __eq__
        """
        return hash(self.to_bytes())

    # --- INTERNAL --- #
    def _private_to_public(self, privkey: bytes) -> PubKey:
        """
        Given a 32-byte private key, we return a basic PubKey object
        """
        pk_int = int.from_bytes(privkey, "big")
        return PubKey(pk_int)

    @classmethod
    def from_master_seed(cls, seed: bytes, version: bytes = BIP44_XPRV):
        # 1. Run the HMAC-512
        seed_hash = hmac_sha512(key=SEED_KEY, message=seed)

        # 2. Get private_key in bytes and chain code
        privkey, chain_code = seed_hash[:32], seed_hash[32:]

        # 3. Use 0 values for remaining params
        return cls(privkey, chain_code, depth=0, parent_fingerprint=b'\x00' * 4, child_number=0, version=version)

    @classmethod
    def from_address(cls, address: str):
        """
        Given a str address, we decode and return the from_serial method
        """
        serial_address = decode_base58(address)
        return cls.from_serial(serial_address)

    @classmethod
    def from_serial(cls, byte_stream: bytes | BytesIO):
        """
        We read in the serialized extended key and verify the checksum
        """
        # We modify to bytesIO for easy of use
        stream = get_stream(byte_stream)

        # Get parts
        version = read_stream(stream, 4, "version")
        depth = read_stream(stream, 1, "depth")
        parent_fingerprint = read_stream(stream, 4, "parent_fingerprint")
        child_number = read_stream(stream, 4, "index")
        chain_code = read_stream(stream, 32, "chain_code")
        key_data = read_stream(stream, 33, "key_data")
        checksum = read_stream(stream, 4, "checksum")

        # Verify checksum
        preimage = version + depth + parent_fingerprint + child_number + chain_code + key_data
        calc_checksum = hash256(preimage)[:4]
        if calc_checksum != checksum:
            raise ValueError("Decoding error. Checksum doesn't match serial value")

        # Clean up
        key_data = key_data[1:] if key_data[0] == 0 else key_data
        depth = int.from_bytes(depth, "big")
        child_number = int.from_bytes(child_number, "big")

        return cls(key_data, chain_code, depth, parent_fingerprint, child_number, version)

    # --- PROPERTIES --- #
    @property
    def is_private(self):
        return len(self.key_data) == 32

    @property
    def is_public(self):
        return len(self.key_data) == 33

    @property
    def is_mainnet(self):
        chunk = self.version[:2]  # First two bytes
        return chunk == b'\x04\x88'

    @property
    def is_testnet(self):
        return self.version[:2] == b'\x04\x35'

    # --- METHODS --- #

    def to_bytes(self):
        """
        returns the serialized version of the key
        version || depth || parent fingerprint || index || chain code || key data || checksum
        """
        key_data = b'\x00' + self.key_data if self.is_private else self.key_data
        parts = [
            self.version,
            self.depth.to_bytes(1, "big"),
            self.parent_fingerprint,
            self.child_number.to_bytes(4, "big"),
            self.chain_code,
            key_data
        ]
        preimage = b''.join(parts)
        checksum = hash256(preimage)[:4]
        return preimage + checksum

    def address(self):
        serialized = self.to_bytes()
        preimage, checksum = serialized[:-4], serialized[-4:]
        return encode_base58(preimage + checksum)

    def fingerprint(self) -> bytes:
        """
        Calculate the fingerprint of the key
        """
        if self.is_private:
            pubkey = self._private_to_public(self.key_data).compressed()
        else:
            pubkey = self.key_data

        pubkey_hash = hash160(pubkey)
        return pubkey_hash[:4]

    def derive_child(self, index: int):
        """
        Derive a child at the given index
        """
        # --- Validate Key Type --- #
        if self.is_public and index >= HARDENED_INDEX:
            raise ExtendedKeyError("Cannot derive hardened child from public key")

        # --- Prepare data for HMAC --- #
        index_bytes = index.to_bytes(4, "big")

        if index >= HARDENED_INDEX:
            # Hardened derivation: use private key
            if self.is_public:
                raise ExtendedKeyError("Cannot perform hardened derivation with public key")
            data = b'\x00' + self.key_data + index_bytes
        else:
            # Non-hardened derivation: use public key
            if self.is_private:
                # Convert private key to public key for HMAC data
                pubkey_data = self._private_to_public(self.key_data).compressed()
            else:
                # Already have public key data
                pubkey_data = self.key_data
            data = pubkey_data + index_bytes

        # --- HMAC SHA512 --- #
        key_hash = hmac_sha512(key=self.chain_code, message=data)
        child_chain_code = key_hash[32:]
        tweak = key_hash[:32]

        # Get tweak_int modulo the order
        tweak_int = int.from_bytes(tweak, 'big') % SECP256K1.order

        # Validate tweak
        if tweak_int == 0 or tweak_int >= SECP256K1.order:
            return self.derive_child(index + 1)

        # Calculate keys
        if self.is_private:
            child_priv_key = (int.from_bytes(self.key_data, "big") + tweak_int) % SECP256K1.order
            child_key_data = child_priv_key.to_bytes(32, "big")
        else:
            pubkey_pt = PubKey.from_compressed(self.key_data).to_point()
            tweak_pt = SECP256K1.multiply_generator(tweak_int)
            child_pubkey_pt = SECP256K1.add_points(pubkey_pt, tweak_pt)
            child_pubkey = PubKey.from_point(child_pubkey_pt)
            child_key_data = child_pubkey.compressed()

        return ExtendedKey(
            version=self.version,
            depth=self.depth + 1,
            parent_fingerprint=self.fingerprint(),
            child_number=index,
            chain_code=child_chain_code,
            key_data=child_key_data
        )

    def get_pubkey(self) -> "ExtendedKey":
        """
        Return the correspinding ExtendedKey public key
        """
        # Public Key
        if self.is_public:
            return self

        # Private Key
        priv_key_int = int.from_bytes(self.key_data, "big")
        compressed_pubkey = PubKey(priv_key_int).compressed()
        return ExtendedKey(
            key_data=compressed_pubkey,
            depth=self.depth,
            parent_fingerprint=self.parent_fingerprint,
            child_number=self.child_number,
            chain_code=self.chain_code,
            version=self.version
        )

    # --- DISPLAY --- #
    def to_dict(self):
        _serialcheck = self.to_bytes()
        serial = _serialcheck[:-4]
        checksum = _serialcheck[-4:]
        first_key = "prvkey" if self.is_private else "pubkey"
        return {
            first_key: self.key_data.hex(),
            "chain_code": self.chain_code.hex(),
            "depth": self.depth,
            "parent_fingerprint": self.parent_fingerprint.hex(),
            "child_number": self.child_number,
            "version": self.version.hex(),
            "serialized": serial.hex(),
            "checksum": checksum.hex(),
            "address": self.address()
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


# --- TESTING --- #
if __name__ == "__main__":
    # known_seed = bytes.fromhex(
    #     "9cb46907973280fff5662cf4e02bb148de5cee73d02feaa57b5aed80bbc6166b5b16ecb2eeb97c4205754e78905eaea920dc59358ab3f0bd0e5117279826f968")
    # known_mxprv = ExtendedKey.from_master_seed(known_seed, BIP44_XPRV)
    # print(f"KNOWN MXPRV: {known_mxprv.to_json()}")
    # known_child = known_mxprv.derive_child(1)
    # print(f"KNOWN CHILD: {known_child.to_json()}")
    # print(f"CHILD XPUB: {known_child.get_pubkey().to_json()}")
    known_xprv = \
        "xprv9tuogRdb5YTgcL3P8Waj7REqDuQx4sXcodQaWTtEVFEp6yRKh1CjrWfXChnhgHeLDuXxo2auDZegMiVMGGxwxcrb2PmiGyCngLxvLeGsZRq"
    known_xpub = \
        "xpub67uA5wAUuv1ypp7rEY7jUZBZmwFSULFUArLBJrHr3amnymkUEYWzQJz13zLacZv33sSuxKVmerpZeFExapBNt8HpAqtTtWqDQRAgyqSKUHu"

    recovered_xprv = ExtendedKey.from_address(known_xprv)
    recovered_xpub = ExtendedKey.from_address(known_xpub)

    print(f"RECOVERED XPRV: {recovered_xprv.to_json()}")
    print(f"RECOVERED XPUB: {recovered_xpub.to_json()}")

    random_address = \
        "xprv9yqWgH7zf7Zi8NLMf9XAzr5irCrAaLoQjixC26K4SxuQGu3Ev7ZEZB3ysA6d96QDXhMjncGRLHwLAcvp4hrWT5tPCpS2zNLMMSAYpqeaQyQ"
    random_xkey = ExtendedKey.from_address(random_address)
    print(f"RANDOM XKEY: {random_xkey.to_json()}")

    another_rando = \
        "zpub6qB8QQWuTFgeBeRFguPvsrMu19NEduRLzp1VDghrN8itgBbMVJepvtqxs5dxWTARyT4u6zr93pVj1RUaRoxycEvgaeCH9SByNNTsSGY5ZfA"
    another_xkey = ExtendedKey.from_address(another_rando)
    print(f"ANOTHER XKYE: {another_xkey.to_json()}")
