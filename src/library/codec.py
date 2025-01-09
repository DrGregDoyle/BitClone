"""
Methods for encoding and decoding
"""
import re

from src.library.bech32 import convertbits, bech32_encode, bech32_decode, Encoding
from src.library.ecc import secp256k1
from src.library.hash_functions import hash256
from src.logger import get_logger

logger = get_logger(__name__)

# --- BASE58 ENCODING --- #
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def encode_base58(hex_string: str) -> str:
    """
    Given a hex string we return a base58 encoded string.
    (Error handling will be performed ahead of calling the function.}
    """
    # Setup
    base = len(BASE58_ALPHABET)
    n = int(hex_string, 16)
    encoded_string = ""

    # Encode into Base58
    while n > 0:
        temp_index = n % base
        n = n // base
        encoded_string = BASE58_ALPHABET[temp_index] + encoded_string

    # Handle leading zeros in the hexadecimal string
    leading_zeros = len(re.match(r"^0*", hex_string).group(0)) // 2
    encoded_string = ("1" * leading_zeros) + encoded_string

    # Debug log
    # logger.debug(f"Hex String: {hex_string} -> Base58: {encoded_string}")
    return encoded_string


def encode_base58check(data: str):
    """
    Given a hexadecimal string, we return the base58Check encoding
    """
    checksum = hash256(bytes.fromhex(data))[:4].hex()  # First 4 bytes of HASH256(data) as hex chars
    # logger.debug(f"DATA: {data}\nCHECKSUM: {checksum}")
    return encode_base58(data + checksum)


def decode_base58check(data: str):
    """
    Given a string of base58Check chars, we decode it and return data and checksum.
    Raise ValueError if checksum fails
    """
    decoded_data = decode_base58(data)
    new_data, checksum = decoded_data[:-8], decoded_data[-8:]  # 4 bytes = 8 hex chars
    test_checksum = hash256(bytes.fromhex(new_data))[:4].hex()
    if test_checksum != checksum:
        raise ValueError("Decoded checksum does not equal given checksum")
    return new_data, checksum


def decode_base58(address: str) -> str:
    """
    Given a base58 encoded string, return the corresponding hexadecimal representation of the underlying integer.
    """
    # Create an integer to hold the result
    total = 0

    # Reverse the base58 string, so we can read characters from left to right
    base58 = address[::-1]

    # We sum the corresponding index value of a given character multiplied by 58 to an increasing power corresponding
    # to the length of the address
    for i in range(len(base58)):
        char = base58[i]
        char_i = BASE58_ALPHABET.index(char)
        total += char_i * pow(58, i)

    # Get hexadecimal representation
    hex_string = hex(total)[2:]

    # Handle leading 1s in the Base58 address
    # Each leading '1' represents a leading zero byte in the hexadecimal string
    leading_zeros = len(re.match(r"^1*", address).group(0))
    hex_string = ("00" * leading_zeros) + hex_string

    # Ensure even length of the hexadecimal string
    if len(hex_string) % 2 != 0:
        hex_string = "0" + hex_string

    # Logging
    logger.debug(f"Base58: {address} -> Hex String: {hex_string}")

    return hex_string


# --- BECH32 ENCODING --- #
def encode_bech32(pubkeyhash: str):
    """
    Returns the Bech32 encoding of the provided public key hash.

    Parameters
    ----------
    pubkeyhash : str
        A hexadecimal string representing the public key hash.

    Returns
    -------
    str
        A Bech32-encoded address.
    """

    # Ensure pubkey_hash is exactly 20 bytes
    if len(pubkeyhash) != 40:
        logger.debug(f"PUBKEY_HASH LENGTH: {len(pubkeyhash)}")
        raise ValueError("P2WPKH pubkey hash must be exactly 20 bytes.")

    # Convert 8-bit data to 5-bit using the reference convertbits function
    converted_data = convertbits(bytes.fromhex(pubkeyhash), 8, 5, pad=False)
    if converted_data is None:
        raise ValueError("Failed to convert data from 8-bit to 5-bit.")

    # Prepend version byte (0x00 for SegWit v0)
    converted_data = [0] + converted_data

    # Submit converted_data using "bc" as hrp
    bech32_address = bech32_encode(hrp="bc", data=converted_data, spec=Encoding.BECH32)

    # Decode to verify checksum
    hrp, decoded_data, spec = bech32_decode(bech32_address)
    if hrp != 'bc' or decoded_data is None:
        raise ValueError("Checksum verification failed.")
    return bech32_address


def decode_bech32(bech32_address: str):
    """
    Given a bech32 address we return the pubkeyhash
    """
    # Use reference bech32_decode function to get hrp, data before encoding, and spec used
    hrp, decoded_data, spec = bech32_decode(bech32_address)

    # Remove prepended version byte
    del decoded_data[0]

    # Convert 5-bit data to 8-bit using the reference convertbits function
    converted_data = convertbits(decoded_data, 5, 8, pad=False)
    logger.debug(f"CONVERTED DATA: {converted_data}")

    # Return hex string of pubkeyhash
    return bytes(converted_data).hex()


# --- ECC KEY COMPRESSION --- #
CURVE = secp256k1()


def compress_public_key(*args) -> bytes:
    """
    Accepts either:
       1) a single tuple of two integers, or
       2) two integers individually.
    """
    if len(args) == 1:
        # Expect args[0] to be a tuple
        if not isinstance(args[0], tuple):
            raise TypeError("Expected a single tuple of two integers.")
        x, y = args[0]  # Unpack the tuple
    elif len(args) == 2:
        # Expect two individual integers
        x, y = args
    else:
        raise TypeError("Expected either one tuple or two integers as arguments.")

    # Verify x and y are integers
    if not (isinstance(x, int) and isinstance(y, int)):
        raise TypeError("Tuple must contain two integers.")

    prefix = 0x02 if (y % 2) == 0 else 0x03

    # Convert prefix to single byte and x_int to 32-byte big-endian
    prefix_byte = prefix.to_bytes(1, 'big')
    x_bytes = x.to_bytes(32, 'big')

    return prefix_byte + x_bytes


def decompress_public_key(compressed_key: bytes) -> tuple:
    if len(compressed_key) != 33:
        raise ValueError("Invalid compressed public key length (must be 33 bytes).")

    prefix = compressed_key[0]
    if prefix not in (0x02, 0x03):
        raise ValueError("Invalid public key prefix (must be 0x02 or 0x03).")

    # Extract x-coordinate
    x = int.from_bytes(compressed_key[1:], byteorder='big')

    # Get one possible value of y
    y1 = CURVE.find_y_from_x(x)

    # Get other possible value of y
    y2 = CURVE.p - y1

    # Check parity of y_candidate. If it doesn't match prefix, use the other root.
    #  - prefix 0x02 => y should be even
    #  - prefix 0x03 => y should be odd
    y = y1 if (y1 & 1) == (prefix & 1) else y2

    return x, y


if __name__ == "__main__":
    test_data = "053dca04f0b6a594a43ac7af7315338118299fce44"
    test_encoding = encode_base58check(test_data)
    print(f"ENCODING: {test_encoding}")
    v_d, v_c = decode_base58check(test_encoding)
    print(f"RECOVERED DATA: {v_d}")
    print(f"ORIGINAL DATA : {test_data}")

    # from secrets import randbits
    #
    # random_point = randbits(256)
    # random_point = CURVE.multiply_generator(random_point)
    # print(f"Random point hex: {hex(random_point[0]), hex(random_point[1])}")
    # cpk = compress_public_key(random_point[0], random_point[1])
    # print(f"COMPRESSED PUBLIC KEY: {cpk.hex()}")
    # rkp = decompress_public_key(cpk)
    # print(f"DECOMPRESSED PUBLIC KEY: {hex(rkp[0]), hex(rkp[1])}")
