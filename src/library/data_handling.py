"""
Methods for handling data in BitClone
"""
import re
import struct
from io import BytesIO

from src.logger import get_logger

logger = get_logger(__name__)


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

    # Remove 0x prefix if present
    hex_string = (hex_string[2:] if hex_string.startswith('0x') else hex_string).lower()

    # Validate hex string
    if len(hex_string) % 2 != 0 or not re.fullmatch(r'^[0-9a-f]+$', hex_string):
        raise ValueError("Invalid hex format: must be an even-length hexadecimal string.")
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


def bits_to_target_from_hex(bits: str) -> str:
    check_hex(bits)
    return bits_to_target(bytes.fromhex(bits)).hex()


# --- TESTING
if __name__ == "__main__":
    # target_hex = "00000000ffff0000000000000000000000000000000000000000000000000000"
    # bits_hex = "1d00ffff"
    #
    # t_to_b = target_to_bits_from_hex(target_hex)
    # b_to_t = bits_to_target_from_hex(bits_hex)
    # print(f"TARGET TO BITS: {target_hex} --> {t_to_b}")
    # print(f"BITS TO TARGET: {bits_hex} --> {b_to_t}")
    # print(f"TARGET TO BITS EQUALS BITS HEX: {t_to_b == bits_hex}")
    # print(f"BITS TO TARGET EQUALS TARGET HEX: {b_to_t == target_hex}")
    zero_cs = write_compact_size(0)
    print(f"ZERO COMPACT SIZE: {zero_cs}")
    print(f"READ COMPACT SIZE: {read_compact_size(zero_cs)}")
