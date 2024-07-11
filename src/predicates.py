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
    Data is assumed to be given in natural byte order. The instance variable "reverse" will display the data in
    reverse byte order.
    """

    def __init__(self, data: str | bytes):
        # Get data
        data = bytes.fromhex(data) if isinstance(data, str) else data

        # Get properties
        self.bytes = data
        self.hex = self.bytes.hex()
        self.reverse = "".join([self.hex[x:x + 2] for x in reversed(range(0, len(self.hex), 2))])


class Endian:
    """
    Given an integer and optional byte length, we return it's little-endian format as either bytes or hex
    """

    def __init__(self, num: int, byte_size=None):
        self.length = num.bit_length() if byte_size is None else byte_size
        self.num = num

    @property
    def bytes(self):
        return self.num.to_bytes(length=self.length, byteorder="little")

    @property
    def hex(self):
        return self.bytes.hex()

    def increment(self):
        self.num += 1


# --- TESTING
from src.library.hash_func import hash256

if __name__ == "__main__":
    txid = hash256("Hello world!")
    bo = ByteOrder(txid)
    print(f"TX ID: Natural byte order: {txid}")
    print(f"BYTE ORDER HEX: {bo.hex}")
    print(f"BYTE ORDER REVERSE: {bo.reverse}")
