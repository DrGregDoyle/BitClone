"""
The Services enum class
"""
from enum import IntFlag

__all__ = ["Services", "InvType"]


class Services(IntFlag):
    UNNAMED = 0x00
    NODE_NETWORK = 0x01
    NODE_GETUTXO = 0x02
    NODE_BLOOM = 0x04
    NODE_WITNESS = 0x08
    NODE_XTHIN = 0x10
    NODE_NETWORK_LIMITED = 0x0400


class InvType(IntFlag):
    ERROR = 0x00
    MSG_TX = 0x01
    MSG_BLOCK = 0x02
    MSG_FILTERED_BLOCK = 0x03
    MSG_CMPCT_BLOCK = 0x04
    MSG_WITNESS_TX = 0x40000001
    MSG_WITNESS_BLOCK = 0x40000002
    MSG_FILTERED_WITNESS_BLOCK = 0x40000003
