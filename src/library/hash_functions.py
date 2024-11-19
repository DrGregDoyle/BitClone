"""
Hash functions - All hash functions return the corresponding bytes digest
"""
import hashlib
import hmac
from typing import Any

from src.library.data_handling import Data
from src.logger import get_logger

logger = get_logger(__name__)


def get_data(data: Any):
    _data = None
    try:
        _data = Data(data)
    except ValueError:
        logger.error(f"Incorrect type used: {type(data)}")
    return _data


def sha1(data: Any):
    _data = get_data(data)
    if _data is not None:
        return hashlib.sha1(_data.bytes).digest()
    return None


def sha256(data: Any):
    _data = get_data(data)
    if _data is not None:
        return hashlib.sha256(_data.bytes).digest()
    return None


def hash256(data: Any):
    return sha256(sha256(data))


def ripemd160(data: Any):
    r = hashlib.new("ripemd160")
    _data = get_data(data)
    if _data is not None:
        r.update(_data.bytes)
        return r.digest()
    return None


def hmac512(key: Any, data: Any):
    _key = get_data(key)
    _data = get_data(data)
    return hmac.new(key=_key.bytes, msg=_data.bytes, digestmod=hashlib.sha512).digest()


def hash160(data: Any):
    return ripemd160(sha256(data))


def pbkdf2(salt: Any, data: Any, iterations: int = 2048):
    _salt = get_data(salt)
    _data = get_data(data)
    for _ in range(iterations):
        _data = Data(hmac512(_salt.bytes, _data.bytes))
    return _data.bytes


# --- TESTING
if __name__ == "__main__":
    data1 = "deadbeef"
    key = data1
    salt = "mnemonic"
    password = "update auto axis"
    _sha256 = sha256(data1).hex()
    _hash256 = hash256(data1).hex()
    _hash160 = hash160(data1).hex()
    _hmac512 = hmac512(key, data1).hex()
    _pbkdf2 = pbkdf2(salt, password).hex()
    print(f"SHA256: {_sha256}")
    print(f"HASH256: {_hash256}")
    print(f"HASH160: {_hash160}")
    print(f"HMAC512: {_hmac512}")
    print(f"PBKDF2: {_pbkdf2}")
