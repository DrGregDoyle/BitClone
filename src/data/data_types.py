"""
The various ENUM classes indicating different types
"""

from enum import IntEnum

__all__ = ["InvType", "BloomType", "RejectType"]


class InvType(IntEnum):
    ERROR = 0
    MSG_TX = 1
    MSG_BLOCK = 2
    MSG_FILTERED_BLOCK = 3
    MSG_CMPCT_BLOCK = 4
    MSG_WITNESS_TX = 0x40000001  # or (1<<30)+MSG_TX
    MSG_WITNESS_BLOCK = 0x40000002  # or (1<<30)+MST_BLOCK
    MSG_FILTERED_WITNESS_BLOCK = 0x40000003  # or (1<<30)+MSG_FILTERED_BLOCK


class BloomType(IntEnum):
    BLOOM_UPDATE_NONE = 0
    BLOOM_UPDATE_ALL = 1
    BLOOM_UPDATE_P2PUBKEY_ONLY = 2

    def to_byte(self):
        """
        1-byte serialization
        """
        return self.value.to_bytes(1, "little")


class RejectType(IntEnum):
    REJECT_MALFORMED = 0x01
    REJECT_INVALID = 0x10
    REJECT_OBSOLETE = 0x11
    REJECT_DUPLICATE = 0x12
    REJECT_NONSTANDARD = 0x40
    REJECT_DUST = 0x41
    REJECT_INSUFFICIENTFEE = 0x42
    REJECT_CHECKPOINT = 0x43

    def to_byte(self):
        return self.value.to_bytes(1, "little")


class NodeType(IntEnum):
    NODE_NETWORK = pow(2, 0)
    NODE_GETUTXO = pow(2, 1)
    NODE_BLOOM = pow(2, 2)
    NODE_WITNESS = pow(2, 3)
    NODE_XTHIN = pow(2, 4)
    NODE_COMPACT_FILTERS = pow(2, 6)
    NODE_NETWORK_LIMITED = pow(2, 10)

    def byte_format(self):
        """
        Returns the little-endian byte representation of the integer
        """
        return self.value.to_bytes(8, "little")
