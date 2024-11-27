"""
HD Wallet class
"""
from secrets import randbits

from src.library.data_handling import is_binary, Data

ENTROPY_BITLENGTH = 256


def get_entropy(bit_length: int = ENTROPY_BITLENGTH):
    random_number = randbits(bit_length)
    return format(random_number, f"0{bit_length}b")


if __name__ == "__main__":
    e1 = get_entropy()
    e2 = Data(e1)
    print(f"IS BINARY: {is_binary(e1)}")
    print(f"ENTROPY 1: {e1}")
    print(f"DATA CLASS BINARY: {e2.binary}")
    print(f"BINARY STRINGS THE SAME?: {e1 == e2.binary}")
