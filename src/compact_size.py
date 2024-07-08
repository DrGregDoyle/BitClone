# --- COMPACTSIZE CLASS --- #
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


def decode_compact_size(data: str | bytes):
    """
    Decode accepts either hex string or bytes object
    """
    data = data.hex() if isinstance(data, bytes) else data  # Data is now a hex string

    first_byte = int.from_bytes(bytes.fromhex(data[:2]), byteorder="big")
    match first_byte:
        case 0xfd | 0xfe | 0xff:
            l_index = 2
            diff = first_byte - 0xfb
            r_index = 2 + pow(2, diff)
        case _:
            l_index = 0
            r_index = 2
    num = int.from_bytes(bytes.fromhex(data[l_index: r_index]), byteorder="little")
    return num, r_index


class ByteOrder:
    BIG = "big-endian"
    LITTLE = "little-endian"

    def __init__(self, data: int | str | bytes, length: int):
        """
        A ByteOrder object stores data in little and big-endian format, along with little-endian-hex and big-endian-hex
        """
        # Get data as integer
        if isinstance(data, int):
            num = data
        elif isinstance(data, str):
            num = int(data, 16)
        else:
            num = int(data.hex(), 16)

        # Get related values
        self.num = num
        self.big = num.to_bytes(length=length, byteorder="big")
        self.little = num.to_bytes(length=length, byteorder="little")
        self.big_int = int(self.big.hex(), 16)
        self.little_int = int(self.little.hex(), 16)

    def __len__(self):
        return len(self.little.hex())


if __name__ == "__main__":
    bo = ByteOrder("02000000", 4)
    print(bo.little.hex())
    print(bo.big.hex())
    print(bo.endian)
