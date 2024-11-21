"""
Hash functions
"""
import hashlib
import hmac
from enum import Enum
from typing import Any

from src.library.data_handling import Data, get_data
from src.logger import get_logger

logger = get_logger(__name__)


class HashType(Enum):
    SHA256 = "sha256"
    HASH256 = "hash256"
    HASH160 = "hash160"
    RIPEMD160 = "ripemd160"


def tagged_hash_function(tag: str | Any, data: Data | Any, hash_type: HashType) -> Data:
    _tag = get_data(tag)
    _data = get_data(data)

    match hash_type:
        case HashType.SHA256:
            _hashed_tag = sha256(_tag)
            return sha256(_hashed_tag.bytes + _hashed_tag.bytes + _data.bytes)
        case HashType.HASH256:
            _hashed_tag = hash256(_tag)
            return hash256(_hashed_tag.bytes + _hashed_tag.bytes + _data.bytes)
        case HashType.RIPEMD160:
            _hashed_tag = ripemd160(_tag)
            return ripemd160(_hashed_tag.bytes + _hashed_tag.bytes + _data.bytes)
        case HashType.HASH160:
            _hashed_tag = hash160(_tag)
            return hash160(_hashed_tag.bytes + _hashed_tag.bytes + _data.bytes)
        case _:
            raise ValueError(f"Incorrect HashType value: {hash_type}")


def sha1(data: Any):
    _data = get_data(data)
    if _data is not None:
        return hashlib.sha1(_data.bytes).digest()
    return None


def sha256(data: Any) -> Data | None:
    _data = get_data(data)
    if _data is not None:
        return Data(hashlib.sha256(_data.bytes).digest())
    logger.error(f"Data type used in sha256 not one of str | int | bytes: {type(data)}")
    return None


def hash256(data: Any):
    _data = get_data(data)
    if _data is not None:
        return sha256(sha256(_data))
    logger.error(f"Data type used in hash256 not one of str | int | bytes: {type(data)}")
    return None


def ripemd160(data: Any):
    _data = get_data(data)
    if _data is not None:
        h = hashlib.new("ripemd160")
        h.update(_data.bytes)
        return Data(h.digest())
    logger.error(f"Data type used in ripemd160 not one of str | int | bytes: {type(data)}")
    return None


def hash160(data: Any):
    _data = get_data(data)
    if _data is not None:
        return ripemd160(sha256(_data))
    logger.error(f"Data type used in hash160 not one of str | int | bytes: {type(data)}")
    return None


#
def hmac512(key: Any, data: Any):
    _key = get_data(key)
    _data = get_data(data)
    return hmac.new(key=_key.bytes, msg=_data.bytes, digestmod=hashlib.sha512).digest()


def pbkdf2(salt: Any, data: Any, iterations: int = 2048):
    _salt = get_data(salt)
    _data = get_data(data)
    for _ in range(iterations):
        _data = Data(hmac512(_salt.bytes, _data.bytes))
    return _data.bytes


# --- TESTING
if __name__ == "__main__":
    _tag = 'BIP0340/aux'
    _data = 'deadbeef'
    _val = tagged_hash_function(_tag, _data, HashType.SHA256)
    print(_val.hex)
