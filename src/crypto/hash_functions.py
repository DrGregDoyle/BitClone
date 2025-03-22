"""
Hash functions
"""
import hashlib
import hmac
from enum import Enum, auto
from typing import Callable

import unicodedata

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
#         logger.debug(f"Tagged hash function failed to convert tag to data: {e}")
#         raise ValueError(f"Invalid data: {tag}") from e
#
#     # Get tagged hash
#     tagged_hash = hash_function(function_type, data=tag)
#
#     # Prep data
#     data = get_data(data)
#     hash_block = tagged_hash + tagged_hash + data
#     return hash_function(function_type, hash_block)

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
    zerohash1 = sha256(bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"))
    print(f"SHA256('0000000000000000000000000000000000000000000000000000000000000000'): {zerohash1.hex()}")
    zerohash2 = sha256(zerohash1)
    print(f"SHA256(SHA256('0000000000000000000000000000000000000000000000000000000000000000'): {zerohash2.hex()}")
    zerodoublehash = hash256(bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"))
    print(f"HASH256('0000000000000000000000000000000000000000000000000000000000000000'): {zerodoublehash.hex()}")

    test_tx_hex = \
        "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"
    tx_hash = hash256(bytes.fromhex(test_tx_hex))
    print(f"HASH256 for TEST TX: {tx_hash.hex()}")
