"""
Classes for proper encoding
"""


class CompactSize:
    """
    Given a non-negative integer values < 2^64, we return its compactSize encoding. The class maintains both a byte
    and hex encoding.
    """

    def __init__(self, num: int):
        self.bytes = self._get_bytes(num)  # Bytes
        self.hex = self.bytes.hex()  # Hex string
        self.num = num  # Actual integer value

    @staticmethod
    def _get_bytes(num: int):
        if 0 <= num <= 0xfc:
            return num.to_bytes(length=1, byteorder="little")
        elif 0xfd <= num <= 0xffff:
            b1 = 0xfd.to_bytes(length=1, byteorder="big")
            b2 = num.to_bytes(length=2, byteorder="little")
            return b1 + b2
        elif 0x10000 <= num <= 0xffffffff:
            b1 = 0xfe.to_bytes(length=1, byteorder="big")
            b2 = num.to_bytes(length=4, byteorder="little")
            return b1 + b2
        elif 0x100000000 <= num <= 0xffffffffffffffff:
            b1 = 0xff.to_bytes(length=1, byteorder="big")
            b2 = num.to_bytes(length=8, byteorder="little")
            return b1 + b2
        else:
            raise ValueError("Number is too big to be CompactSize encoded.")


class ByteOrder:
    """
    Input hex string or bytes object is assumed to be in REVERSE BYTE ORDER. We transform into a natural byte order object.
    """

    def __init__(self, data: str | bytes, reverse=True):
        # Get integer from data
        num = int(data, 16) if isinstance(data, str) else int(data.hex(), 16)

        # Get byte size
        length = len(data) // 2 if isinstance(data, str) else len(data)

        # Natural byte order | little-endian
        self.bytes = num.to_bytes(length=length, byteorder="little") if reverse else num.to_bytes(length=length,
                                                                                                  byteorder="big")
        self.hex = self.bytes.hex()

        # Reverse byte order
        self.display = "".join([self.hex[x:x + 2] for x in reversed(range(0, len(self.hex), 2))])


class Endian:
    """
    Given an integer and optional byte length, we return it's little-endian format as either bytes or hex
    """

    def __init__(self, num: int, byte_size=None):
        length = num.bit_length() * 8 if byte_size is None else byte_size

        self.num = num
        self.bytes = num.to_bytes(length=length, byteorder="little")
        self.hex = self.bytes.hex()
