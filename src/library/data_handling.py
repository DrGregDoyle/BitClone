"""
Methods for handling data in BitClone
"""
import struct
from io import BytesIO


def check_hex(hex_string: str) -> str:
    """
    Checks the validity of the hex string

    Returns:
        hex_string: formatter hex string

    Raises:
        ValueError: If hex_string is not of str type
        ValueError: If the hex_string contains a character outside the hex alphabet.
    """
    # Type
    if not isinstance(hex_string, str):
        raise ValueError(f"Input not of str type. Type; {type(hex_string)}")

    if hex_string.startswith("0x"):
        hex_string = hex_string[2:]
    hex_string = hex_string.lower()

    # Check the string
    if not all(c in "0123456789abcedf" for c in hex_string):
        raise ValueError("String contains non hexadecimal characters")
    return hex_string


def read_compact_size(stream: bytes | BytesIO):
    """
    Reads a Bitcoin CompactSize (a.k.a. varint) from the given stream.

    The stream can be either a file-like object (supporting .read())
    or a bytes object.

    Returns:
        int: The integer value represented by the CompactSize encoding.
    """
    # Check type
    if isinstance(stream, bytes):
        stream = BytesIO(stream)
    if not isinstance(stream, BytesIO):
        raise ValueError(f"Expected byte data stream, received {type(stream)}")

    prefix = stream.read(1)
    if len(prefix) == 0:
        raise ValueError("Insufficient data to read CompactSize prefix.")

    prefix_val = prefix[0]

    if prefix_val < 0xfd:
        # Single-byte value
        return prefix_val
    elif prefix_val == 0xfd:
        # Next 2 bytes as uint16 (little-endian)
        raw = stream.read(2)
        if len(raw) < 2:
            raise ValueError("Insufficient data to read CompactSize (0xfd).")
        return struct.unpack("<H", raw)[0]
    elif prefix_val == 0xfe:
        # Next 4 bytes as uint32 (little-endian)
        raw = stream.read(4)
        if len(raw) < 4:
            raise ValueError("Insufficient data to read CompactSize (0xfe).")
        return struct.unpack("<I", raw)[0]
    else:
        # prefix_val == 0xff -> Next 8 bytes as uint64 (little-endian)
        raw = stream.read(8)
        if len(raw) < 8:
            raise ValueError("Insufficient data to read CompactSize (0xff).")
        return struct.unpack("<Q", raw)[0]


def write_compact_size(value: int) -> bytes:
    """
    Encodes an integer into a Bitcoin CompactSize (varint) byte sequence.

    Args:
        value (int): The integer value to encode.

    Returns:
        bytes: The bytes representing the CompactSize encoding of `value`.
    """
    if value < 0:
        raise ValueError("Negative values are not allowed in CompactSize encoding.")

    if value < 0xfd:
        return struct.pack("B", value)
    elif value <= 0xffff:
        return b'\xfd' + struct.pack("<H", value)
    elif value <= 0xffffffff:
        return b'\xfe' + struct.pack("<I", value)
    else:
        return b'\xff' + struct.pack("<Q", value)


def byte_format(data: bytes, length: int):
    diff = length - len(data)
    if diff == 0:
        return data
    elif diff > 0:
        return data.rjust(diff, b'\x00')  # Pad with 0 bytes
    else:
        raise ValueError("Data size greater than length")


def check_length(data: bytes, length: int, value: str):
    if len(data) != length:
        raise ValueError(f"Insufficient data for {value}.")


def to_little_bytes(num: int, length: int = None):
    """
    Returns little-endian encoding of the given num. Will be of specified length if included
    """
    length = (num.bit_length() + 7) // 8 if length is None else length
    return num.to_bytes(length, "little")


def from_little_bytes(little_bytes: bytes) -> int:
    """
    Returns integer from little-endian encoded bytes object
    """
    return int.from_bytes(little_bytes, "little")


def target_to_bits_from_hex(target: str) -> str:
    # Check str
    check_hex(target)
    return target_to_bits(bytes.fromhex(target)).hex()


def target_to_bits(target: bytes) -> bytes:
    # Find the first significant byte
    sig_dig = target.lstrip(b'\x00')
    exp = len(sig_dig).to_bytes(1, "big")
    coeff = sig_dig[:3]
    return exp + coeff


def bits_to_target(bits: bytes) -> bytes:
    exp = int.from_bytes(bits[:1], "big")
    coeff = int.from_bytes(bits[1:4], "big")
    target_int = coeff * pow(2, 8 * (exp - 3))
    return target_int.to_bytes(length=32, byteorder="big")


def bits_to_target_from_hex(bits: str) -> str:
    check_hex(bits)
    return bits_to_target(bytes.fromhex(bits)).hex()


# --- TESTING
if __name__ == "__main__":
    target_hex = "00000000000000000005ae3af5b1628dc0000000000000000000000000000000"
    bits_hex = "1705ae3a"

    t_to_b = target_to_bits_from_hex(target_hex)
    b_to_t = bits_to_target_from_hex(bits_hex)
    print(f"TARGET TO BITS: {target_hex} --> {t_to_b}")
    print(f"BITS TO TARGET: {bits_hex} --> {b_to_t}")
