"""
The Extended Key Classes - We have an ABC called Xkey in which Xprv and Xpub classes inherit from
"""

from abc import ABC, abstractmethod

from src.core import XKEYS

SEED_KEY = XKEYS.SEED_KEY
CHAINLEN = XKEYS.CHAIN_LENGTH
MAXDEPTH = XKEYS.MAX_DEPTH


class XKey(ABC):
    """
    Abstract base class for HD extended keys (xprv/xpub).
    Holds common BIP32 metadata: chain code, depth, parent fingerprint, child number, version bytes.
    """

    __slots__ = ("chain_code", "depth", "parent_fingerprint", "child_number", "version")

    def __init__(self, chain_code: bytes, depth: int, parent_fingerprint: int, child_number: int,
                 version: dict | None = None):
        # --- Input validation -- #
        # - Chain code
        if not isinstance(chain_code, (bytes, bytearray)) or len(chain_code) != CHAINLEN:
            raise ValueError(f"chain_code must be {CHAINLEN} bytes.")
        # - Depth
        if not (0 <= depth <= MAXDEPTH):
            raise ValueError(f"depth must be in [0,{MAXDEPTH}].")
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
        self.version = version  # if version is not None else _ntwk.BIP44

    @abstractmethod
    def derive_child(self, index: int) -> "XKey":
        """
        Derive a child key.
        Implementation differs for XPrv vs XPub.
        """
        raise NotImplementedError

    @abstractmethod
    def to_xpub(self) -> "XPub":
        """
        Return the public key version (if applicable).
        """
        raise NotImplementedError

    @abstractmethod
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

    @abstractmethod
    def address(self) -> str:
        """
        Return the base58-check serialization of the extended key (xprv/xpub).
        Must be overridden by XPrv / XPub because each must supply the correct key data (private vs. public).
        """
        raise NotImplementedError


class XPrv(XKey):
    pass


class XPub(XKey):
    pass
