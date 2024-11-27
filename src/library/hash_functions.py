"""
Hash functions
"""
import hashlib
from enum import Enum, auto
from typing import Callable

from src.logger import get_logger

logger = get_logger(__name__)


# noinspection PyArgumentList
class HashType(Enum):
    SHA1 = auto()
    SHA256 = auto()
    HASH256 = auto()
    HASH160 = auto()
    RIPEMD160 = auto()


#
#
# def tagged_hash_function(function_type: HashType, data: bytes, tag: bytes):
#     # Format tag for downstream functions
#     try:
#         tag = get_data(tag)
#     except ValueError as e:
#         logger.debug(f"Tagged hash function failed to convert tag to Data: {e}")
#         raise ValueError(f"Invalid data: {tag}") from e
#
#     # Get tagged hash
#     tagged_hash = hash_function(function_type, data=tag)
#
#     # Prep data
#     data = get_data(data)
#     hash_block = tagged_hash + tagged_hash + data
#     return hash_function(function_type, hash_block)


def hash_function(encoded_data: bytes, function_type: HashType):
    # Mapping of HashType enum members to function objects
    functions: dict[HashType, Callable] = {
        HashType.SHA1: sha1,
        HashType.SHA256: sha256,
        HashType.HASH160: hash160,
        HashType.HASH256: hash256,
        HashType.RIPEMD160: ripemd160
    }

    # Retrieve the function based on the Enum member
    func = functions.get(function_type)
    if not func:
        raise ValueError(f"Function '{function_type}' not found.")

    return func(encoded_data)


def tagged_hash_function(encoded_data: bytes, tag: bytes, function_type: HashType):
    # Get hash of tag
    hashed_tag = hash_function(tag, function_type=function_type)

    # Return  HASH(hashed_tag + hashed_tag + encoded_data)
    return hash_function(hashed_tag + hashed_tag + encoded_data, function_type=function_type)


def sha1(encoded_data: bytes) -> bytes:
    return hashlib.sha1(encoded_data).digest()


def sha256(encoded_data: bytes) -> bytes:
    return hashlib.sha256(encoded_data).digest()


def sha512(encoded_data: bytes) -> bytes:
    return hashlib.sha512(encoded_data).digest()


def hash256(encoded_data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(encoded_data)).digest()


def ripemd160(encoded_data: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(encoded_data)
    return h.digest()


def hash160(encoded_data: bytes) -> bytes:
    return ripemd160(sha256(encoded_data))


# def hmac512(data: Data, key: Any):
#     _key = get_data(key)
#     _data = get_data(data)
#     return hmac.new(key=_key.bytes, msg=_data.bytes, digestmod=hashlib.sha512).digest()
#
#
# def pbkdf2(salt: Any, data: Any, iterations: int = 2048):
#     _salt = get_data(salt)
#     _data = get_data(data)
#     for _ in range(iterations):
#         _data = Data(hmac512(_salt.bytes, _data.bytes))
#     return _data.bytes


# --- TESTING
if __name__ == "__main__":
    _tag = 'BIP0340/aux'
    _data = 'deadbeef'
    # _val = tagged_hash_function(_tag, _data, HashType.SHA256)
    # print(_val.hex)
