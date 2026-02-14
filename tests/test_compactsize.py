"""
Test for CompactSize encoding
"""
from random import randint

from src.core.byte_stream import read_compact_size, write_compact_size


def test_read_compactsize():
    """
    We create 4 distinct compact size numbers and verify we can read them
    """
    # Get random ints
    cs_1_int = randint(0, 0xfc)
    cs_2_int = randint(0xfd, 0xffff)
    cs_3_int = randint(0x10000, 0xffffffff)
    cs_4_int = randint(0x100000000, 0xffffffffffffffff)

    # Format to CompactSize encoding
    cs1 = cs_1_int.to_bytes(1, "little")
    cs2 = b'\xfd' + cs_2_int.to_bytes(2, "little")
    cs3 = b'\xfe' + cs_3_int.to_bytes(4, "little")
    cs4 = b'\xff' + cs_4_int.to_bytes(8, "little")

    # Verify decoding yields original integers
    assert read_compact_size(cs1) == cs_1_int, "CompactSize decoding fails for 1-byte integer"
    assert read_compact_size(cs2) == cs_2_int, "CompactSize decoding fails for 2-byte integer"
    assert read_compact_size(cs3) == cs_3_int, "CompactSize decoding fails for 4-byte integer"
    assert read_compact_size(cs4) == cs_4_int, "CompactSize decoding fails for 8-byte integer"


def test_write_compactsize():
    """
    We create 4 distinct integers and verify they encode to proper CompactSize format
    """
    # Get random ints in each range
    cs_1_int = randint(0, 0xfc)
    cs_2_int = randint(0xfd, 0xffff)
    cs_3_int = randint(0x10000, 0xffffffff)
    cs_4_int = randint(0x100000000, 0xffffffffffffffff)

    # Expected CompactSize encodings
    expected_cs1 = cs_1_int.to_bytes(1, "little")
    expected_cs2 = b'\xfd' + cs_2_int.to_bytes(2, "little")
    expected_cs3 = b'\xfe' + cs_3_int.to_bytes(4, "little")
    expected_cs4 = b'\xff' + cs_4_int.to_bytes(8, "little")

    # Verify encoding produces expected bytes
    assert write_compact_size(cs_1_int) == expected_cs1, "CompactSize encoding fails for 1-byte integer"
    assert write_compact_size(cs_2_int) == expected_cs2, "CompactSize encoding fails for 2-byte integer"
    assert write_compact_size(cs_3_int) == expected_cs3, "CompactSize encoding fails for 4-byte integer"
    assert write_compact_size(cs_4_int) == expected_cs4, "CompactSize encoding fails for 8-byte integer"
