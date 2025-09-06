"""
Shortcuts for the most popular hash functions. Each function returns the bytes digest
"""
import hashlib
import hmac

import unicodedata

__all__ = ["hash160", "hash256", "hmac_sha512", "pbkdf2", "ripemd160", "sha1", "sha256", "sha512", "schnorr_aux_hash",
           "schnorr_challenge_hash", "schnorr_nonce_hash", "tagged_sha256", "tapbranch_hash", "tapleaf_hash",
           "taptweak_hash"]


# --- SHA --- #
def sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


# --- RIPEMD --- #

def ripemd160(data: bytes) -> bytes:
    _h = hashlib.new("ripemd160")
    _h.update(data)
    return _h.digest()


# --- BTC HASH FUNCTIONS --- #

def hash256(data: bytes) -> bytes:
    """SHA256(SHA256(data))"""
    return sha256(sha256(data))


def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data))"""
    return ripemd160(sha256(data))


# --- WALLET HASHES --- #
def hmac_sha512(key: bytes, message: bytes) -> bytes:
    return hmac.new(key=key, msg=message, digestmod=hashlib.sha512).digest()


def pbkdf2(mnemonic: list, passphrase='', iterations=2048, dklen=64) -> bytes:
    """
    Derives a cryptographic key from a mnemonic (list of words) using PBKDF2-HMAC-SHA512.

    mnemonic: A list of words representing the mnemonic.
    passphrase: An optional passphrase string (default: empty string).
    iterations: Number of iterations for PBKDF2 (default: 2048).
    dklen: Length of the derived key in bytes (default: 64 bytes).
    return: The derived key as a hexadecimal string.
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


# --- TAGGED HASH FUNCTIONS --- #

def tagged_sha256(tag: bytes, data: bytes) -> bytes:
    # Get tagged hash
    tagged_hash = sha256(tag)

    # Return SHA256( tagged_hash || tagged_hash || data )
    return sha256(tagged_hash + tagged_hash + data)


# --- TAPROOT TAGGED HASH FUNCTIONS --- #
def tapleaf_hash(data: bytes) -> bytes:
    return tagged_sha256(b'TapLeaf', data)


def tapbranch_hash(data: bytes) -> bytes:
    return tagged_sha256(b'TapBranch', data)


def taptweak_hash(data: bytes) -> bytes:
    return tagged_sha256(b'TapTweak', data)


# --- SCHNORR BIP0340 TAGGED HASH FUNCTIONS --- #
def schnorr_aux_hash(data: bytes) -> bytes:
    return tagged_sha256(b'BIP0340/aux', data)


def schnorr_nonce_hash(data: bytes) -> bytes:
    return tagged_sha256(b'BIP0340/nonce', data)


def schnorr_challenge_hash(data: bytes) -> bytes:
    return tagged_sha256(b'BIP0340/challenge', data)
