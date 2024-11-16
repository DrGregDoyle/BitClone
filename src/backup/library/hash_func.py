"""
Hash library for BitClone

All hash functions can accept hex strings, byte strings or arbitrary strings.
"""
import hmac
from hashlib import sha256, sha512, sha1

from ripemd.ripemd160 import ripemd160

from src.backup.library.base58 import BASE58_LIST


def get_bytes(data: str | bytes) -> bytes:
    try:
        return bytes.fromhex(data) if isinstance(data, str) else data
    except ValueError:
        return data.encode()


def op_sha1(data: str | bytes):
    data = get_bytes(data)
    return sha1(data).hexdigest()


def hash256(data: str | bytes):
    data = get_bytes(data)
    return sha256(sha256(data).digest()).hexdigest()


def sha_256(data: str | bytes):
    data = get_bytes(data)
    return sha256(data).hexdigest()


def hash160(data: str) -> str:
    data = get_bytes(data)
    return ripemd160(sha256(data).digest()).hex()


def hmac512(key: str, data: str) -> str:
    byte_key = get_bytes(key)
    byte_data = get_bytes(data)
    return hmac.new(key=byte_key, msg=byte_data, digestmod=sha512).hexdigest()


def pbkdf2(data: str, salt: str, iterations=2048):
    """
    For the PBKDF2, we assume the key and data are arbitrary strings. Hence we can byte-encode them using .encode().
    """
    byte_key = get_bytes(salt)
    message = get_bytes(data)
    for _ in range(iterations):
        message = hmac.new(byte_key, message, sha512).digest()
    return message.hex()


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


# --- TESTING
if __name__ == "__main__":
    data = "02e3af28965693b9ce1228f9d468149b831d6a0540b25e8a9900f71372c11fb277"
    hash_result = hash160(data)
    print(f"HASH RESULT: {hash_result}")
