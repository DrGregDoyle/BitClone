"""
Methods for encoding and decoding
"""
import re

from src.library.bech32 import convertbits, bech32_encode, bech32_decode, Encoding
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
    logger.debug(f"Hex String: {hex_string} -> Base58: {encoded_string}")
    return encoded_string


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


if __name__ == "__main__":
    test_hex = "00fff9029e7788f84d34b53aa0575b1336e21d45ddc8ad5d4f"
    test_address = encode_base58(test_hex)
    decoded_address = decode_base58(test_address)
    print(f"DECODE SUCCESSFUL: {test_hex == decoded_address}")
