"""
Helper methods for various aspects of Script
"""
from src.crypto.hash_functions import tagged_hash_function
from src.data import Taproot, write_compact_size

_tap = Taproot

__all__ = ["tapleaf_hash", "tapbranch_hash", "taptweak_hash"]


def tapleaf_hash(leaf_script: bytes, version_byte: bytes = _tap.VERSION_BYTE):
    """
    BIP341 TapLeaf hash: tagged_hash( leaf_version || compact_size(len(script)) || script )
    """
    payload = version_byte + write_compact_size(len(leaf_script)) + leaf_script
    return tagged_hash_function(payload, tag=_tap.TAPLEAF)


def tapbranch_hash(data: bytes):
    return tagged_hash_function(data, tag=_tap.TAPBRANCH)


def taptweak_hash(data: bytes):
    return tagged_hash_function(data, tag=_tap.TAPTWEAK)
