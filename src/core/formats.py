"""
The Bitcoin standard formats

"""
from typing import Final

__all__ = ["BECH32CODE", "BLOCK", "DATA", "ECC", "MAGICBYTES", "NETWORK", "SCRIPT", "TAPROOT", "TX", "WALLET", "XKEYS"]


class BECH32CODE:
    BECH32: Final[int] = 1
    BECH32M: Final[int] = 2


class BLOCK:
    VERSION: Final[int] = 4  # Byte size
    BIP65_VERSION: Final[int] = 0x04  # BIP65 --> uses OP_CHECKLOCKTIMEVERIFY for locktime calculations
    PREV_BLOCK: Final[int] = 32
    TIME: Final[int] = VERSION
    NONCE: Final[int] = VERSION
    BITS: Final[int] = VERSION
    MERKLE_ROOT: Final[int] = PREV_BLOCK
    TIMESTAMP_FORMAT: Final[str] = "%A, %d %B %Y %H:%M:%S"  # Display


class DATA:
    """
    Constants used in data manipulation
    """
    MAX_COMPACTSIZE = 0xffffffffffffffff
    TARGET: Final[int] = 32
    BITS: Final[int] = 4


class ECC:
    COORD_BYTES: Final[int] = 32


class MAGICBYTES:
    MAINNET: Final[bytes] = b'\xf9\xbe\xb4\xd9'
    TESTNET: Final[bytes] = b'\x0b\x11\x09\x07'
    REGTEST: Final[bytes] = b'\xfa\xbf\xb5\xda'
    SIGNET: Final[bytes] = b'\x0a\x03\xcf\x40'
    NAMECOIN: Final[bytes] = b'\xf9\xbe\xb4\xfe'

    @classmethod
    def __contains__(cls, item):
        """Allow 'in' operator to check if magic bytes are valid"""
        return item in (cls.MAINNET, cls.TESTNET, cls.REGTEST)

    @classmethod
    def __iter__(cls):
        """Allow iteration over magic bytes values"""
        return iter([cls.MAINNET, cls.TESTNET, cls.REGTEST])


class NETWORK:
    """
    Network protocol constants
    """
    ALLOWED_COMMANDS: Final[frozenset] = frozenset([
        "version", "verack", "addr", "inv", "getdata", "getblocks", "getheaders",
        "tx", "block", "headers", "getaddr", "ping", "pong", "notfound", "mempool",
        "reject", "filterload", "filteradd", "filterclear", "merkleblock",
        "sendheaders", "feefilter", "sendcmpct", "cmpctblock", "getblocktxn", "blocktxn", "testing"
    ])

    DEPRECATED_COMMANDS: Final[frozenset] = frozenset([
        "submitorder", "checkorder", "reply", "alert"
    ])

    COMMAND_LENGTH: Final[int] = 12


class SCRIPT:
    """
    Constants in use in the Script
    """
    MAX_BITNUM: Final[int] = 4
    MAX_STACK: Final[int] = 1000
    COMMON_VALUES: Final[dict] = {
        0: b'',
        -1: b'\x81'
    }
    PUBKEY_LENS: Final[list] = [33, 65]  # Allowable lengths for a public key


class TAPROOT:
    VERSION_BYTE: Final[bytes] = b'\xc0'
    SIGHASH_EPOCH: Final[bytes] = b'\x00'
    PUBKEY_BYTELEN: Final[int] = 32
    PUBKEY_VERSION: Final[bytes] = b'\x00'


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
    BIP68_VERSION: Final[int] = 2  # Tx.version
    MARKERFLAG: Final[int] = 2
    INDEX: Final[int] = 4


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
    ENTROPY_BYTES: Final[int] = 16
    WORD_BITS: Final[int] = 11
    BITLEN_KEY: Final[int] = "bit_length"
    WORD_KEY: Final[str] = "word_count"
    CHECKSUM_KEY: Final[str] = "checksum_bits"
    SEED_ITERATIONS: Final[int] = 2048
    DKLEN: Final[int] = 64


class UTXO_SERIAL:
    """
    Constants for UTXO serialization
    """
    OUTPOINT: Final[int] = 36
    AMOUNT: Final[int] = 8


class XKEYS:
    """
    Constants related to the extended public and private keys
    """
    SEED_KEY: Final[bytes] = b'Bitcoin seed'
    CHAIN_LENGTH: Final[int] = 32
    MAX_DEPTH: Final[int] = 255

    # Version bytes for different key types
    TESTNET_PRV: Final[bytes] = bytes.fromhex("04358394")
    TESTNET_PUB: Final[bytes] = bytes.fromhex("043587cf")
    BIP44_XPRV: Final[bytes] = bytes.fromhex("0488ade4")
    BIP44_XPUB: Final[bytes] = bytes.fromhex("0488b21e")
    BIP49_XPRV: Final[bytes] = bytes.fromhex("049d7878")
    BIP49_XPUB: Final[bytes] = bytes.fromhex("049d7cb2")
    BIP84_XPRV: Final[bytes] = bytes.fromhex("04b2430c")
    BIP84_XPUB: Final[bytes] = bytes.fromhex("04b24746")
    VERSIONS: Final[list] = [
        BIP44_XPRV, BIP44_XPUB, BIP49_XPRV, BIP84_XPRV, BIP84_XPUB, TESTNET_PRV, TESTNET_PUB
    ]

    # Hardened derivation threshold
    HARDENED_OFFSET: Final[int] = 0x80000000
    MAX_INDEX: Final[int] = 0xffffffff
