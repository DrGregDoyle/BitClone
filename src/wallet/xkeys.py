"""
Extended Keys (xpub/xprv) Implementation for BitClone Wallet
Implements BIP32 Hierarchical Deterministic Wallet key derivation

#TODO: Need to create an address function and a from_address class method
#TODO: Need to do a from_master_seed class method to create the XPRv
"""
import json

from src.core import ExtendedKeyError, XKEYS
from src.cryptography import SECP256K1, hash160, hmac_sha512
from src.data import encode_base58check

__all__ = ["PubKey"]

MAINNET_PRV = XKEYS.MAINNET_PRIVATE
MAINNET_PUB = XKEYS.MAINNET_PUBLIC
TESTNET_PRV = XKEYS.TESTNET_PRIVATE
TESTNET_PUB = XKEYS.TESTNET_PUBLIC
HARDENED_INDEX = XKEYS.HARDENED_OFFSET


class PubKey:
    """
    Used for Serializaing a public key in BitClone
    """
    __slots__ = ("x", "y")

    def __init__(self, private_key: int):
        _pubkey_pt = SECP256K1.multiply_generator(private_key)
        self.x, self.y = _pubkey_pt

    def compressed(self) -> bytes:
        """
        Returns a compressed public key
        """
        y_byte = b'\x02' if self.y % 2 == 0 else b'\x03'
        return y_byte + self.x.to_bytes(32, "big")

    def uncompressed(self) -> bytes:
        """
        Returns an uncompressed public key
        """
        return b'\x04' + self.x_bytes() + self.y_bytes()

    def x_bytes(self):
        return self.x.to_bytes(32, "big")

    def y_bytes(self):
        return self.y.to_bytes(32, "big")


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
                 version: int,
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

    # --- INTERNAL --- #
    def _private_to_public(self, privkey: bytes) -> PubKey:
        """
        Given a 32-byte private key, we return a basic PubKey object
        """
        pk_int = int.from_bytes(privkey, "big")
        return PubKey(pk_int)

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

    def address(self):
        key = b'\x00' + self.key_data if self.is_public else self.key_data
        preimage = self.version.to_bytes(4, "big") + self.depth.to_bytes(1, "big") + self.parent_fingerprint + \
                   self.child_number.to_bytes(4, "big") + self.chain_code + key
        return encode_base58check(preimage)

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

        # ---  Prep data for HMAC--- #
        index_bytes = index.to_bytes(4, "big")
        n = SECP256K1.order

        # Normal Keys
        if index < HARDENED_INDEX:
            # Same data format for public and private
            data = self._private_to_public(self.key_data).compressed() + index_bytes
        # Hardened Keys
        else:
            # Check if pubkey
            if self.is_public:
                raise ExtendedKeyError("Cannot created hardened child from pubkey")
            data = b'\x00' + self.key_data + index_bytes

        # --- HMAC SHA512 --- #
        key_hash = hmac_sha512(key=self.chain_code, message=data)
        child_chain_code = key_hash[32:]
        child_key = key_hash[:32]

        child_key_int = (int.from_bytes(child_key, 'big') + int.from_bytes(self.key_data, 'big')) % n

        if self.is_private:
            # Private key derivation
            child_key_data = child_key_int.to_bytes(32, "big")
        else:
            # Public key derivation
            child_key_data = PubKey(child_key_int).compressed()

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
            version=MAINNET_PUB
        )

    # --- DISPLAY --- #
    def to_dict(self):
        first_key = "prvkey" if self.is_private else "pubkey"
        return {
            first_key: self.key_data.hex(),
            "chain_code": self.chain_code.hex(),
            "depth": self.depth,
            "parent_fingerprint": self.parent_fingerprint.hex(),
            "child_number": self.child_number,
            "version": hex(self.version)
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


# --- TESTING --- #
if __name__ == "__main__":
    known_privkey = bytes.fromhex("cde1b29f62627e8cdbffe851ffbddbe33584e3e1506ddc6d4affcac820f66bd7")
    known_chaincode = bytes.fromhex("e5786c92bfb55e143427a6873cc738e2bd95dfd0b654ebbd732a431e00259acb")
    master_xprv = ExtendedKey(key_data=known_privkey, chain_code=known_chaincode, depth=0,
                              parent_fingerprint=b'\x00\x00\x00\x00', child_number=0, version=TESTNET_PRV)

    print(f"MASTER XPRV: {master_xprv.to_json()}")
    child_key = master_xprv.derive_child(4)
    print(f"CHILD XPRV: {child_key.to_json()}")
    print(f"CHILD XPUB {child_key.get_pubkey().to_json()}")
