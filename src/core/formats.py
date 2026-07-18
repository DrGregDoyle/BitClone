"""
The Bitcoin standard formats

"""
from typing import Final

__all__ = ["BECH32CODE", "BLOCK", "DATA", "ECC", "MAGICBYTES", "NETWORK", "SCRIPT", "TAPROOT",
           "TX", "WALLET", "UTXO_SERIAL", "XKEYS"]


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
    HEADER_LENGTH: Final[int] = VERSION + PREV_BLOCK + MERKLE_ROOT + TIME + BITS + NONCE
    TIMESTAMP_FORMAT: Final[str] = "%A, %d %B %Y %H:%M:%S"  # Display
    GENESIS_BLOCK_BITS: Final[bytes] = b'\x1d\x00\xff\xff'


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
    ALLOWED_MAGIC: Final[tuple[bytes, ...]] = (MAINNET, TESTNET, REGTEST, SIGNET)

    @classmethod
    def __contains__(cls, item):
        """Allow 'in' operator to check if magic bytes are valid"""
        return item in cls.ALLOWED_MAGIC

    @classmethod
    def __iter__(cls):
        """Allow iteration over magic bytes values"""
        return iter(cls.ALLOWED_MAGIC)


class NETWORK:
    """
    Network protocol constants
    """
    PROTOCOL_VERSION: Final[int] = 70016
    MIN_PROTOCOL_VERSION: Final[int] = 70001
    USER_AGENT: Final[str] = "/BitClone:0.1.0/"
    MAINNET_PORT: Final[int] = 8333
    TESTNET_PORT: Final[int] = 18333
    REGTEST_PORT: Final[int] = 18444
    SIGNET_PORT: Final[int] = 38333

    MAGIC_LENGTH: Final[int] = 4
    COMMAND_LENGTH: Final[int] = 12
    PAYLOAD_SIZE_LENGTH: Final[int] = 4
    CHECKSUM_LENGTH: Final[int] = 4
    HEADER_LENGTH: Final[int] = MAGIC_LENGTH + COMMAND_LENGTH + PAYLOAD_SIZE_LENGTH + CHECKSUM_LENGTH
    MAX_PAYLOAD_SIZE: Final[int] = 4_000_000
    MAX_PRE_VERACK_MESSAGES: Final[int] = 10

    PROTOCOL_VERSION_LENGTH: Final[int] = 4
    SERVICES_LENGTH: Final[int] = 8
    TIMESTAMP_LENGTH: Final[int] = 8
    NET_ADDR_TIMESTAMP_LENGTH: Final[int] = 4
    IP_ADDRESS_LENGTH: Final[int] = 16
    PORT_LENGTH: Final[int] = 2
    NONCE_LENGTH: Final[int] = 8
    BLOCK_HEIGHT_LENGTH: Final[int] = 4
    HASH_LENGTH: Final[int] = 32
    INVENTORY_TYPE_LENGTH: Final[int] = 4
    FEE_RATE_LENGTH: Final[int] = 8
    BLOOM_HASH_FUNCTIONS_LENGTH: Final[int] = 4
    BLOOM_TWEAK_LENGTH: Final[int] = 4
    BLOOM_FLAGS_LENGTH: Final[int] = 1
    REJECT_CODE_LENGTH: Final[int] = 1
    FILTER_TYPE_LENGTH: Final[int] = 1
    FILTER_START_HEIGHT_LENGTH: Final[int] = 4
    MERKLE_TX_COUNT_LENGTH: Final[int] = 4
    HEADERS_TX_COUNT_LENGTH: Final[int] = 1
    COMPACT_BLOCK_ANNOUNCE_LENGTH: Final[int] = 1
    COMPACT_BLOCK_VERSION_LENGTH: Final[int] = 8
    SHORT_ID_LENGTH: Final[int] = 6
    SHORT_ID_KEY_LENGTH: Final[int] = 16
    SHORT_ID_HASH_LENGTH: Final[int] = 8
    NET_ADDR_LENGTH: Final[int] = SERVICES_LENGTH + IP_ADDRESS_LENGTH + PORT_LENGTH

    MAX_INVENTORY_ENTRIES: Final[int] = 50_000
    MAX_GETBLOCKS_RESULTS: Final[int] = 500
    MAX_HEADERS_RESULTS: Final[int] = 2_000
    MAX_COMPACT_FILTERS_PER_REQUEST: Final[int] = 1_000

    MAX_SHORTID_NONCE: Final[int] = 0xffffffffffffffff
    INV_HASH_SIZE: Final[int] = HASH_LENGTH


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
    OUTPOINT: Final[int] = 36


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
    HEIGHT: Final[int] = 4
    IS_COINBASE: Final[int] = 1


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
