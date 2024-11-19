"""
Testing primitives
"""

from hashlib import sha256
from random import randint

from src.library.primitive import Endian, CompactSize, ByteOrder


def test_endian():
    # Test correct encoding
    length1 = 2
    num1 = randint(a=0x00, b=0xff)
    hex1 = format(num1, "02x")  # 1 byte
    e0 = Endian(num1)
    e1 = Endian(num1, length=length1)

    assert e0.hex == hex1
    assert e1.hex == hex1 + "00"
    assert e1.big == "00" + hex1


def test_compact_size():
    num1 = CompactSize(0xfc)
    num2 = CompactSize(0xfd)
    num3 = CompactSize(0xffff)
    num4 = CompactSize(0xffffffff)
    num5 = CompactSize(0xffffffffffffffff)

    assert num1.hex == "fc"
    assert num2.hex == "fdfd00"
    assert num3.hex == "fdffff"
    assert num4.hex == "feffffffff"
    assert num5.hex == "ffffffffffffffffff"


def test_byte_order():
    data = sha256("Hello World!".encode()).hexdigest()
    bdata = ByteOrder(data)
    assert bdata.hex == data
    assert bdata.reverse == "".join(data[x:x + 2] for x in reversed(range(0, len(data), 2)))
