"""
The Bitcoin standard formats
"""
from typing import Final

__all__ = ["ECC", "WALLET", "XKEYS", "BECH32CODE", "DATA", "TX"]


class DATA:
    """
    Constants used in data manipulation
    """
    MAX_COMPACTSIZE = 0xffffffffffffffff


class ECC:
    COORD_BYTES: Final[int] = 32


class WALLET:
    """
    We provide a Mnemonic dictionary which is BIP39 compliant. This forces the Mnemonic to be of a certain size
    depending on the entropy byte length chosen
    """
    MNEMONIC: Final[dict] = {
        16: {"bit_length": 128, "word_count": 12, "checksum_bits": 4},
        20: {"bit_length": 160, "word_count": 15, "checksum_bits": 5},
        24: {"bit_length": 192, "word_count": 18, "checksum_bits": 6},
        28: {"bit_length": 224, "word_count": 21, "checksum_bits": 7},
        32: {"bit_length": 256, "word_count": 24, "checksum_bits": 8},
    }
    DEFAULT_ENTROPY_BYTES: Final[int] = 16
    WORD_BITS: Final[int] = 11
    BITLEN_KEY: Final[int] = "bit_length"
    WORD_KEY: Final[str] = "word_count"
    CHECKSUM_KEY: Final[str] = "checksum_bits"
    SEED_ITERATIONS: Final[str] = 2048
    DKLEN: Final[str] = 64


class XKEYS:
    """
    Constants related to the extended public and private keys
    """
    SEED_KEY = b'Bitcoin seed'
    CHAIN_LENGTH = 32
    MAX_DEPTH = 255

    # Version bytes for different key types
    TESTNET_PRIVATE = bytes.fromhex("04358394")
    TESTNET_PUBLIC = bytes.fromhex("043587cf")
    BIP44_XPRV = bytes.fromhex("0488ade4")
    BIP44_XPUB = bytes.fromhex("0488b21e")
    BIP49_XPRV = bytes.fromhex("049d7878")
    BIP49_XPUB = bytes.fromhex("049d7cb2")
    BIP84_XPRV = bytes.fromhex("04b2430c")
    BIP84_XPUB = bytes.fromhex("04b24746")

    # Hardened derivation threshold
    HARDENED_OFFSET = 0x80000000
    MAX_INDEX = 0xffffffff


class BECH32CODE:
    BECH32 = 1
    BECH32M = 2


class TX:
    """
    Transaction byte sizes
    """
    TXID: Final[int] = 32
    VOUT: Final[int] = 4
    SEQUENCE: Final[int] = 4
    AMOUNT: Final[int] = 8
    VERSION: Final[int] = 4
    LOCKTIME: Final[int] = 4
