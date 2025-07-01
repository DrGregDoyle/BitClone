"""
The Enum class for the rejection types for messaging
"""

from enum import Enum

__all__ = ["RejectType"]


class RejectType(Enum):
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
