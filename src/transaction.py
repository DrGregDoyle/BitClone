"""
A page for the Transaction class

Notes:
    -If using segwit, the marker must be zero (0x00) and the flag must be nonzero (0x01).
    -If not using segwit, the marker and flag must not be included in the transaction

 === Structure of a transaction ===
    Version: 4 bytes
    Marker: segwit optional 1 byte
    Flag: segwit optional 1 byte
    Inputs:
        --
        count: compactSize unsigned integer (variable integer)
        outpoint:
            --
            txid: 32 byte
            output_index: 4 byte (index starting at 0)
        input script:
        sequence:
    Outputs:
        --
        count: compactSize integer (greater than 0)
        amount: 8-byte *signed* integer (min = 0, max = 21 000 000 000 000 000)
        script_length: compactSize integer

"""


class CompactSize:

    def get_encoding(self, n: int):
        """
        We return the encoding of n assuming 0 <= n < 2^32
        """
        raw_hex = hex(n)[2:]
        prepend = "0x"

        if 0xFC <= n <= 0xFFFF:
            prepend += "FD"
        elif 0X10000 <= n <= 0xFFFFFFFF:
            prepend += "FE"
        elif 0x100000000 <= n <= 0xffffffffffffffff:
            prepend += "FF"

        return prepend + raw_hex


class Transaction:
    VERSION = 4  # 4 bytes for version field

    def __init__(self):
        pass


# --- TESTING --- #
if __name__ == "__main__":
    cs = CompactSize()
    print(cs.get_encoding(10))
    print(cs.get_encoding(0x123456789))
    print(cs.get_encoding(4886718345))
