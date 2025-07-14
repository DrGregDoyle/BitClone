"""
The Bloom type class for Bloom filters
"""

from enum import Enum

__all__ = ["BloomType"]


class BloomType(Enum):
    BLOOM_UPDATE_NONE = 0
    BLOOM_UPDATE_ALL = 1
    BLOOM_UPDATE_P2PUBKEY_ONLY = 2

    def to_byte(self):
        """
        1-byte serialization
        """
        return self.value.to_bytes(1, "little")
