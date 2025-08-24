"""
Methods for handling data in BitClone
"""

__all__ = ["byte_format", "to_little_bytes",
           "target_to_bits", "bits_to_target", "bits_to_target_int",
           "bytes_to_binary_string", "bytes_to_nibbles_string", "little_bytes_to_binary_string"]


def byte_format(data: bytes, length: int):
    diff = length - len(data)
    if diff == 0:
        return data
    elif diff > 0:
        return data.rjust(length, b'\x00')  # Pad with 0 bytes
    else:
        raise ValueError("data size greater than length")


def bytes_to_binary_string(b: bytes):
    return bin(int.from_bytes(b, 'big'))[2:].zfill(len(b) * 8)


def little_bytes_to_binary_string(b: bytes):
    return ''.join(f"{byte:08b}"[::-1] for byte in b)


def bytes_to_nibbles_string(b: bytes):
    bits = little_bytes_to_binary_string(b)
    return " ".join([bits[i:i + 4] for i in range(0, len(bits), 4)])


def to_little_bytes(num: int, length: int = None):
    """
    Returns little-endian encoding of the given num. Will be of specified length if included
    """
    length = (num.bit_length() + 7) // 8 if length is None else length
    return num.to_bytes(length, "little")


def target_to_bits(target: bytes) -> bytes:
    """Convert a full 32-byte target into compact bits encoding."""
    # Find the first significant byte
    first_nonzero = next((i for i, b in enumerate(target) if b != 0), len(target))

    # Compute exponent (Bitcoin defines this as 32 - index)
    exp = (32 - first_nonzero).to_bytes(1, "big")

    # Extract first 3 significant bytes
    sig_dig = target[first_nonzero:first_nonzero + 3]

    # If the coefficient has fewer than 3 bytes, pad with zeros
    coeff = sig_dig.ljust(3, b'\x00')

    # If the first byte of the coefficient is >= 0x80, prepend `00` and increase exponent
    if coeff[0] >= 0x80:
        coeff = b'\x00' + coeff[:2]  # Shift the coefficient
        exp = (int.from_bytes(exp, "big") + 1).to_bytes(1, "big")  # Increment exponent

    return exp + coeff


def bits_to_target(bits: bytes) -> bytes:
    target_int = bits_to_target_int(bits)
    return target_int.to_bytes(length=32, byteorder="big")


def bits_to_target_int(bits: bytes) -> int:
    exp = int.from_bytes(bits[:1], "big")
    coeff = int.from_bytes(bits[1:4], "big")
    target_int = coeff * pow(2, 8 * (exp - 3))
    return target_int

#
# if __name__ == "__main__":
#     format_test1 = byte_format(b'\x00', 4)
#     print(format_test1.hex())
