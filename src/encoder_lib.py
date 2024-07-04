"""
A library for common encoding functions
"""
# --- IMPORTS --- #
import hmac
from binascii import unhexlify
from hashlib import sha256, sha512, sha1

from ripemd.ripemd160 import ripemd160


# --- HASH FUNCTIONS --- #

def op_sha1(data: str):
    return sha1(data.encode()).hexdigest()


def secure_hash_256(data: str):
    """
    Returns hex digest of SHA256(data)
    """
    return sha256(data.encode()).hexdigest()


# def hash256(data: str) -> str:
#     """
#     Returns the hex digest of SHA256(SHA256(data)) - 32-bytes
#     """
#     return sha256(sha256(data.encode()).hexdigest().encode()).hexdigest()


def hash160(data: str) -> str:
    """
    Returns the hex digest of RIPEMD160(SHA256(data)) - 20-bytes
    """
    return ripemd160(sha256(data.encode()).hexdigest()).hexdigest()


def hmac512(key: str, data: str) -> str:
    """
    Returns the hex digest of the HMAC-SHA512(key, data) hash function - 64-bytes (we force 128-char length)
    """
    byte_key = unhexlify(key)  # HMAC takes byte values for key and data
    byte_data = unhexlify(data)
    return hmac.new(key=byte_key, msg=byte_data, digestmod=sha512).hexdigest().zfill(128)


def pbkdf2(key: str, data: str, iterations=2048):
    """
    For the PBKDF2, we assume the key and data are arbitrary strings. Hence we can byte-encode them using .encode().
    """
    byte_key = key.encode()
    message = data.encode()
    for _ in range(iterations):
        message = hmac.new(byte_key, message, sha512).hexdigest().encode()
    return message.decode()


# --- BASE 58 --- #
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_LIST = [x for x in BASE58_ALPHABET]


def base58_check(data: int | str, checksum=True):
    # Make sure data is in hex format
    if isinstance(data, int):
        data = format(data, "0x")

    # Checksum
    if checksum:
        _checksum = hash256(data)[:8]  # Take 4-bytes (8 chars) for checksum
        data += _checksum

    # Convert
    buffer = ""
    data_int = int(data, 16)
    while data_int > 0:
        r = data_int % 58
        buffer = BASE58_LIST[r] + buffer
        data_int = data_int // 58

    return buffer


def decode_base58_check(encoded_data: str, checksum=True):
    total = 0
    data_range = len(encoded_data)
    for x in range(data_range):
        total += BASE58_LIST.index(encoded_data[x:x + 1]) * pow(58, data_range - x - 1)
    if checksum:
        datacheck = format(total, "0x")
        data = datacheck[:-8]
        check = datacheck[-8:]
        assert sha256(data.encode()).hexdigest()[:8] == check
    else:
        data = format(total, "0x")
    return data

# --- BITS/TARGET --- #
