"""
The various ENUM classes indicating different types
"""

from enum import Enum

__all__ = ["InvType"]


# --- INVENTORY TYPE --- #
class InvType(Enum):
    ERROR = 0
    MSG_TX = 1
    MSG_BLOCK = 2
    MSG_FILTERED_BLOCK = 3
    MSG_CMPCT_BLOCK = 4
    MSG_WITNESS_TX = 0x40000001  # or (1<<30)+MSG_TX
    MSG_WITNESS_BLOCK = 0x40000002  # or (1<<30)+MST_BLOCK
    MSG_FILTERED_WITNESS_BLOCK = 0x40000003  # or (1<<30)+MSG_FILTERED_BLOCK
