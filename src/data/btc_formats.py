"""
The classes containing the byte sizes of various BTC fields
"""

__all__ = ["BitcoinFormats"]


class BitcoinFormats:
    """Bitcoin protocol format constants in bytes"""

    class Hash:
        """Hash and digest sizes"""
        SHA256 = 32
        RIPEMD160 = 20
        HASH160 = 20  # RIPEMD160(SHA256(data))
        HASH256 = 32  # SHA256(SHA256(data))
        CHECKSUM = 4
        MERKLE_ROOT = 32
        TRANSACTION_ID = 32
        BLOCK_HASH = 32

    class Keys:
        """Cryptographic key and signature sizes"""
        PRIVATE_KEY = 32
        PUBLIC_KEY_COMPRESSED = 33
        PUBLIC_KEY_UNCOMPRESSED = 65
        SIGNATURE_DER_MAX = 72  # Maximum DER encoded signature
        SIGNATURE_COMPACT = 64  # Compact signature format
        SIGNATURE_RECOVERABLE = 65  # With recovery ID

    class Network:
        """Network protocol field sizes"""
        VERSION = 4
        SERVICES = 8
        TIMESTAMP = 4
        HEADER_SIZE = 4
        HEADER_CHECKSUM = 4
        NONCE = 4
        TARGET = 4
        DIFFICULTY = 4
        COMMAND = 12  # P2P message command
        MESSAGE_HEADER = 24  # Full message header
        PAYLOAD_LENGTH = 4
        MAGIC_BYTES = 4
        SHORTID = 8
        MAX_SHORTID_PAYLOAD = 6
        IP = 16
        PORT = 2

    class Address:
        """Address format sizes"""
        P2PKH = 25  # Pay-to-Public-Key-Hash
        P2SH = 25  # Pay-to-Script-Hash
        BECH32_MIN = 14
        BECH32_MAX = 74
        WIF_COMPRESSED = 38  # Wallet Import Format
        WIF_UNCOMPRESSED = 37

    class Tx:
        """Transaction field sizes"""
        TX_ID = 32
        VOUT = 4
        SEQUENCE = 4
        AMOUNT = 8
        VERSION = 4
        LOCK_TIME = 4
        INPUT_COUNT_MIN = 1  # VarInt minimum
        OUTPUT_COUNT_MIN = 1  # VarInt minimum
        MARKER = 1
        FLAG = 1
        MARKERFLAG = 2
        VALUE = 8  # Satoshi amount
        SCRIPT_LENGTH_MIN = 1  # VarInt minimum
        OUTPOINT = 36  # 32 byte hash + 4 byte index

    class Block:
        """Block structure sizes"""
        HEADER = 80
        VERSION = 4
        PREVIOUS_HASH = 32
        MERKLE_ROOT = 32
        TIMESTAMP = 4
        BITS = 4
        NONCE = 4
        TRANSACTION_COUNT_MIN = 1  # VarInt minimum

    class Inventory:
        """Inventory message sizes"""
        TYPE = 4
        HASH = 32
        ENTRY = 36  # TYPE + HASH
        MAX_ENTRIES = 50000  # Protocol limit

    class Protocol:
        """Protocol values"""
        VERSION = 2

    class MagicBytes:
        """Magic byte constants"""
        MAINNET = bytes.fromhex("f9beb4d9")
        TESTNET = bytes.fromhex("0b110907")
        REGTEST = bytes.fromhex("fabfb5da")

    class Time:
        """Time Formatting for Display"""
        FORMAT = "%Y-%m-%d %H:%M:%S"
