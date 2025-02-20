"""
Methods for encoding and decoding
"""

import re
from typing import Tuple

from src.library.bech32 import convertbits, bech32_encode, bech32_decode, Encoding
from src.library.ecc import secp256k1
from src.library.hash_functions import hash256
from src.logger import get_logger

logger = get_logger(__name__)

# --- BASE58 ENCODING --- #
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def encode_base58(data: bytes) -> str:
    """
    We return the base58 encoding of the given bytes data
    """
    # Setup
    base = len(BASE58_ALPHABET)
    n = int.from_bytes(data, byteorder="big")  # Convert bytes to integer
    encoded_string = ""

    # Encode into Base58
    while n > 0:
        temp_index = n % base
        n = n // base
        encoded_string = BASE58_ALPHABET[temp_index] + encoded_string

    # Handle leading zeros in the byte string
    leading_zeros = len(data) - len(data.lstrip(b'\x00'))
    encoded_string = ("1" * leading_zeros) + encoded_string

    # Convert the Base58 string to a bytes object
    return encoded_string


def decode_base58(data: str) -> bytes:
    """
    Given a base58 encoded string, return the corresponding hexadecimal representation of the underlying integer.
    """
    # Create an integer to hold the result
    total = 0

    # Reverse the base58 string, so we can read characters from left to right
    base58 = data[::-1]

    # We sum the corresponding index value of a given character multiplied by 58 to an increasing power corresponding
    # to the length of the address
    for i in range(len(base58)):
        char = base58[i]
        char_i = BASE58_ALPHABET.index(char)
        total += char_i * pow(58, i)

    # Get bytes from integer
    decoded_bytes = total.to_bytes((total.bit_length() + 7) // 8, "big")

    # Handle leading 1s in the Base58 address
    # Each leading '1' represents a leading zero byte in the hexadecimal string
    leading_zeros = len(re.match(r"^1*", data).group(0))
    decoded_bytes = (b'\x00' * leading_zeros) + decoded_bytes

    return decoded_bytes


def encode_base58check(data: bytes) -> str:
    """
    Given bytes data, we return the base58 encoding along with checksum
    """
    checksum = hash256(data)[:4]  # First 4 bytes of HASH256(data)
    return encode_base58(data + checksum)


def decode_base58check(data: str) -> Tuple[bytes, bytes]:
    """
    Given a string of base58Check chars, we decode it and return data and checksum.
    Raise ValueError if checksum fails
    """
    decoded_bytecheck = decode_base58(data)
    d_bytes, d_checksum = decoded_bytecheck[:-4], decoded_bytecheck[-4:]
    test_checksum = hash256(d_bytes)[:4]
    if test_checksum != d_checksum:
        raise ValueError("Decoded checksum does not equal given checksum")
    return d_bytes, d_checksum


# --- BECH32 ENCODING --- #
def encode_bech32(pubkeyhash: bytes, hrp: str = "bc") -> str:
    """
    Returns the Bech32 encoding of the provided public key hash.

    Parameters
    ----------
    pubkeyhash : bytes
        The pubkeyhash in bytes
    hrp :str
        A string for bech32 encoding

    Returns
    -------
    str
        A Bech32-encoded address.
    """

    # Ensure pubkey_hash is exactly 20 bytes
    if len(pubkeyhash) != 20:
        logger.debug(f"PUBKEY_HASH LENGTH: {len(pubkeyhash)}")
        raise ValueError("P2WPKH pubkey hash must be exactly 20 bytes.")

    # Convert 8-bit data to 5-bit using the reference convertbits function
    converted_data = convertbits(pubkeyhash, 8, 5, pad=False)
    if converted_data is None:
        raise ValueError("Failed to convert data from 8-bit to 5-bit.")

    # Prepend version byte (0x00 for SegWit v0)
    converted_data = [0] + converted_data

    # Submit converted_data using "bc" as hrp
    bech32_address = bech32_encode(hrp=hrp, data=converted_data, spec=Encoding.BECH32)

    # Decode the address to verify checksum
    decoded_hrp, decoded_data, spec = bech32_decode(bech32_address)
    if decoded_hrp != hrp or decoded_data is None or spec != Encoding.BECH32:
        raise ValueError("Checksum verification failed. The generated Bech32 address is invalid.")

    return bech32_address


def decode_bech32(bech32_address: str) -> bytes:
    """
    Given a bech32 address we return the pubkeyhash
    """
    # Use reference bech32_decode function to get hrp, data before encoding, and spec used
    hrp, decoded_data, spec = bech32_decode(bech32_address)

    # Remove prepended version byte
    del decoded_data[0]

    # Convert 5-bit data to 8-bit using the reference convertbits function
    converted_data = convertbits(decoded_data, 5, 8, pad=False)

    # Return byte encoded pubkeyhash
    return bytes(converted_data)


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


# --- WIF PRIVATE KEY --- #
def encode_wif_private_key(private_key: bytes, version_byte: bytes = b"\x80",
                           compression_byte: bytes | None = b"\x01") -> str:
    """
    Given a private key we return the WIF encoding
    """
    hex_key = private_key.hex()
    hex_version_byte = version_byte.hex()
    hex_compression_byte = compression_byte.hex() if compression_byte is not None else ""
    data = hex_version_byte + hex_key + hex_compression_byte
    checksum = hash256(bytes.fromhex(data))[:4].hex()
    logger.debug(f"CHECKSUM: {checksum}")
    return encode_base58(data + checksum)


if __name__ == "__main__":
    # test_privkey = bytes.fromhex("db943987fdd2e80b80e4339dbe45498088245c9c048fe7a8c86ce64a5ff7a61c")
    # encoded_wif = encode_wif_private_key(test_privkey)
    # print(f"WIF ENCODED KEY: {encoded_wif}")
    # encoded_wif_testnet = encode_wif_private_key(test_privkey, version_byte=b"\xef")
    # print(f"WIF TESTNET KEY: {encoded_wif_testnet}")
    # encoded_wif_no_compression = encode_wif_private_key(private_key=test_privkey, compression_byte=None)
    # print(f"WIF KEY NO COMPRESSION: {encoded_wif_no_compression}")
    _pubkeyhash = "be9f8266e6d3808816601ee9abaf2bbafd279b5c"
    _address = encode_bech32(_pubkeyhash)
    print(f"P2WPKH ADDRESS: {_address}")
