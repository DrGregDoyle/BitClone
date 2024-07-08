"""
Hash library for BitClone
"""
import hmac
from hashlib import sha256, sha512, sha1

from ripemd.ripemd160 import ripemd160

from src.library.base58 import BASE58_LIST


def get_bytes(data: str | bytes) -> bytes:
    return bytes.fromhex(data) if isinstance(data, str) else data


def op_sha1(data: str | bytes):
    data = get_bytes(data)
    return sha1(data).hexdigest()


def hash256(data: str | bytes):
    # Convert hex to byte sequence
    binary = get_bytes(data)

    # Hash twice
    hash1 = sha256(binary).digest()
    hash2 = sha256(hash1).digest()

    # Return hex digest
    return hash2.hex()


def sha_256(data: str | bytes):
    encoded_data = get_bytes(data)
    return sha256(encoded_data).hexdigest()


def hash160(data: str) -> str:
    """
    Returns the hex digest of RIPEMD160(SHA256(data)) - 20-bytes
    """
    return ripemd160(sha256(data.encode()).hexdigest()).hexdigest()


def hmac512(key: str, data: str) -> str:
    """
    Returns the hex digest of the HMAC-SHA512(key, data) hash function - 64-bytes (we force 128-char length)
    """
    byte_key = get_bytes(key)
    byte_data = get_bytes(data)
    return hmac.new(key=byte_key, msg=byte_data, digestmod=sha512).hexdigest()


def pbkdf2(key: str, data: str, iterations=2048):
    """
    For the PBKDF2, we assume the key and data are arbitrary strings. Hence we can byte-encode them using .encode().
    """
    byte_key = key.encode()
    message = data.encode()
    for _ in range(iterations):
        message = hmac.new(byte_key, message, sha512).hexdigest().encode()
    return message.decode()


def base58_check(data: int | str, checksum=True):
    # Make sure data is in hex format
    data = format(data, "0x") if isinstance(data, int) else data

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
