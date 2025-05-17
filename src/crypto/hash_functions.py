"""
Hash functions
"""
import hashlib
import hmac
from enum import Enum, auto
from typing import Callable

import unicodedata


class HashType(Enum):
    SHA1 = auto()
    SHA256 = auto()
    HASH256 = auto()
    HASH160 = auto()
    RIPEMD160 = auto()


# SCHNORR
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


def tap_tweak(data: bytes, hash_type: HashType = HashType.SHA256):
    return tagged_hash_function(data, b'TapTweak', hash_type)


def tap_leaf(data: bytes, hash_type: HashType = HashType.SHA256):
    return tagged_hash_function(data, b'TapLeaf', hash_type)


def tap_branch(data: bytes, hash_type: HashType = HashType.SHA256):
    return tagged_hash_function(data, b'TapBranch', hash_type)


# HASHLIB
def sha1(encoded_data: bytes) -> bytes:
    return hashlib.sha1(encoded_data).digest()


def sha256(encoded_data: bytes) -> bytes:
    return hashlib.sha256(encoded_data).digest()


def sha512(encoded_data: bytes) -> bytes:
    return hashlib.sha512(encoded_data).digest()


def hash256(encoded_data: bytes) -> bytes:
    return sha256(sha256(encoded_data))


def ripemd160(encoded_data: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(encoded_data)
    return h.digest()


def hash160(encoded_data: bytes) -> bytes:
    return ripemd160(sha256(encoded_data))


def hmac_sha512(key: bytes, message: bytes) -> bytes:
    return hmac.new(key=key, msg=message, digestmod=hashlib.sha512).digest()


def pbkdf2(mnemonic: list, passphrase='', iterations=2048, dklen=64) -> bytes:
    """
    Derives a cryptographic key from a mnemonic (list of words) using PBKDF2-HMAC-SHA512.

    :param mnemonic: A list of words representing the mnemonic.
    :param passphrase: An optional passphrase string (default: empty string).
    :param iterations: Number of iterations for PBKDF2 (default: 2048).
    :param dklen: Length of the derived key in bytes (default: 64 bytes).
    :return: The derived key as a hexadecimal string.
    """
    # Step 1: Concatenate the mnemonic list into a single string
    mnemonic_str = ' '.join(mnemonic)

    # Step 2: Normalize the mnemonic and passphrase using NFKD
    normalized_mnemonic = unicodedata.normalize('NFKD', mnemonic_str)
    normalized_passphrase = unicodedata.normalize('NFKD', passphrase)

    # Step 3: Prepare the salt ("mnemonic" + normalized passphrase)
    salt = f"mnemonic{normalized_passphrase}".encode('utf-8')

    # Step 4: Encode the normalized mnemonic as UTF-8 bytes
    password_bytes = normalized_mnemonic.encode('utf-8')

    # Step 5: Derive the key using PBKDF2-HMAC-SHA512
    derived_key = hashlib.pbkdf2_hmac('sha512', password_bytes, salt, iterations, dklen)

    # Return the derived key as a hexadecimal string
    return derived_key


# --- TESTING
if __name__ == "__main__":
    data = bytes.fromhex("deadbeef")
    leaf_hash = tagged_hash_function(data, b"TapLeaf", HashType.SHA256)
    print(f"LEAF HASH: {leaf_hash.hex()}")
