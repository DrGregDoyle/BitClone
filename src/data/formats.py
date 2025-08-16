# src/data/formats.py
from typing import Final

__all__ = ["Hashes", "Keys", "Wire", "TxFmt", "AddressFmt", "Display"]


class Hashes:
    SHA256: Final[int] = 32
    RIPEMD160: Final[int] = 20
    HASH160: Final[int] = 20
    CHECKSUM: Final[int] = 4
    TXID: Final[int] = 32
    BLOCKHASH: Final[int] = 32


class Keys:
    PRIV: Final[int] = 32
    PUB_COMP: Final[int] = 33
    PUB_UNCOMP: Final[int] = 65
    SIG_DER_MAX: Final[int] = 72
    SIG_COMPACT: Final[int] = 64
    SIG_RECOVERABLE: Final[int] = 65
    ENTROPY_BITS: Final[int] = 256


class Display:
    TIME_FORMAT: Final[str] = "%Y-%m-%d %H:%M:%S"


class Wire:
    class Network:
        # -- HRP codes for bech32
        HRP_MAIN: Final[str] = 'bc'
        HRP_TEST: Final[str] = 'tb'

        # -- xprv, xpub key byte dicts
        BIP44: Final[dict] = {
            "xprv": bytes.fromhex("0488ade4"),
            "xpub": bytes.fromhex("0488ade4")
        }
        BIP49: Final[dict] = {
            "xprv": bytes.fromhex("049d7878"),
            "xpub": bytes.fromhex("049d7cb2")
        }

        BIP84: Final[dict] = {
            "xprv": bytes.fromhex("04b2430c"),
            "xpub": bytes.fromhex("04b24746")
        }

        # -- magic bytes
        MB_MAIN: Final[bytes] = bytes.fromhex("f9beb4d9")
        MB_TEST: Final[bytes] = bytes.fromhex("0b110907")
        MB_REG: Final[bytes] = bytes.fromhex("fabfb5da")

    class Header:
        MAGIC_LEN: Final[int] = 4
        COMMAND_LEN: Final[int] = 12
        SIZE_LEN: Final[int] = 4
        CHECKSUM_LEN: Final[int] = 4
        TOTAL_LEN: Final[int] = 24

    class NetAddr:
        TIME_LEN: Final[int] = 4
        SERVICES_LEN: Final[int] = 8
        IP_LEN: Final[int] = 16
        PORT_LEN: Final[int] = 2

    class InventoryEntry:
        TYPE_LEN: Final[int] = 4
        HASH_LEN: Final[int] = 32
        ENTRY_LEN: Final[int] = 36
        MAX_ENTRIES: Final[int] = 50000

    class BlockHeader:
        VERSION_LEN: Final[int] = 4
        PREV_HASH_LEN: Final[int] = 32
        MERKLE_ROOT_LEN: Final[int] = 32
        TIME_LEN: Final[int] = 4
        BITS_LEN: Final[int] = 4
        NONCE_LEN: Final[int] = 4
        TOTAL_LEN: Final[int] = 80

    class ShortIDSpec:
        PAYLOAD_LEN: Final[int] = 6  # BIP152 shortid
        PADDED_LEN: Final[int] = 8  # often carried as u64 on wire
        NONCE_LEN: Final[int] = 8

    class CompactBlock:
        TXNUM_LEN: Final[int] = 4
        MERKLE_HASH_LEN: Final[int] = 32
        ANNOUNCE_LEN: Final[int] = 1
        VERSION_LEN: Final[int] = 8
        NONCE_LEN: Final[int] = 8

    class Filter:
        FEERATE_LEN: Final[int] = 8
        NHASH_LEN: Final[int] = 4
        TWEAK_LEN: Final[int] = 4
        FLAG_LEN: Final[int] = 1
        MAXFILTER_VAL: Final[int] = 36000
        MAXNHASH_VAL: Final[int] = 50

    class Node:
        VERSION_LEN: Final[int] = 4
        SERVICES_LEN: Final[int] = 8
        TIME_LEN: Final[int] = 8


class TxFmt:
    VERSION_LEN: Final[int] = 4
    VOUT_LEN: Final[int] = 4
    TXID_LEN: Final[int] = 32
    OUTPOINT_LEN: Final[int] = 36
    SEQUENCE_LEN: Final[int] = 4
    LOCKTIME_LEN: Final[int] = 4
    AMOUNT_LEN: Final[int] = 8
    MARKERFLAG: Final[int] = 2


class AddressFmt:
    P2PKH_LEN: Final[int] = 25
    P2SH_LEN: Final[int] = 25
    BECH32_MIN: Final[int] = 14
    BECH32_MAX: Final[int] = 74
    WIF_COMP: Final[int] = 38
    WIF_UNCOMP: Final[int] = 37
