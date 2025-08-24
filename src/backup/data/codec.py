"""
Methods for encoding and decoding
"""

import re

from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature

from src.backup.crypto import hash256, convertbits, bech32_encode, bech32_decode, Encoding
from src.backup.logger import get_logger

logger = get_logger(__name__)

__all__ = ["encode_base58", "decode_base58", "encode_base58check", "decode_base58check", "encode_bech32",
           "decode_bech32", "encode_der_signature", "decode_der_signature"]

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


def decode_base58check(data: str) -> tuple[bytes, bytes]:
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
def encode_bech32(pubkeydata: bytes, hrp: str = "bc", witver: int = 0) -> str:
    """
    Returns the Bech32 or Bech32m encoding of the provided witness program.

    Parameters
    ----------
    pubkeydata : bytes
        The witness program (e.g. 20 bytes for P2WPKH, 32 bytes for P2TR)
    hrp : str
        Human-readable part (e.g. 'bc' for mainnet, 'tb' for testnet)
    witver : int
        Witness version (0 for P2WPKH/P2WSH, 1 for P2TR)

    Returns
    -------
    str
        A Bech32 or Bech32m encoded address.
    """
    # Check witness version
    if not (0 <= witver <= 16):
        raise ValueError("Witness version must be between 0 and 16.")

    # Convert 8-bit data to 5-bit
    converted_data = convertbits(list(pubkeydata), 8, 5, pad=True)
    if converted_data is None:
        raise ValueError("Failed to convert data from 8-bit to 5-bit.")

    # Prepend version byte (0x00 for SegWit v0)
    converted_data = [witver] + converted_data

    # Choose encoding type
    spec = Encoding.BECH32M if witver > 0 else Encoding.BECH32

    # Submit converted_data using "bc" as hrp
    bech32_address = bech32_encode(hrp=hrp, data=converted_data, spec=spec)

    # Decode the address to verify checksum
    decoded_hrp, decoded_data, dec_spec = bech32_decode(bech32_address)
    if decoded_hrp != hrp or decoded_data is None or dec_spec != spec:
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


# --- DER SIGNATURE ENCODING --- #
def encode_der_signature(r: int, s: int) -> bytes:
    """
    Encodes ECDSA integers r and s into a DER-encoded signature.
    """
    return encode_dss_signature(r, s)


def decode_der_signature(der_sig: bytes) -> tuple[int, int]:
    """
    Decodes a DER-encoded ECDSA signature back into integers r and s.
    """
    return decode_dss_signature(der_sig)


if __name__ == "__main__":
    # test_privkey = bytes.fromhex("db943987fdd2e80b80e4339dbe45498088245c9c048fe7a8c86ce64a5ff7a61c")
    # encoded_wif = encode_wif_private_key(test_privkey)
    # print(f"WIF ENCODED KEY: {encoded_wif}")
    # encoded_wif_testnet = encode_wif_private_key(test_privkey, version_byte=b"\xef")
    # print(f"WIF TESTNET KEY: {encoded_wif_testnet}")
    # encoded_wif_no_compression = encode_wif_private_key(private_key=test_privkey, compression_byte=None)
    # print(f"WIF KEY NO COMPRESSION: {encoded_wif_no_compression}")
    _pubkeyhash = bytes.fromhex("be9f8266e6d3808816601ee9abaf2bbafd279b5c")
    _address = encode_bech32(_pubkeyhash)
    print(f"P2WPKH ADDRESS: {_address}")
