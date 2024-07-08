"""
Hash library for BitClone
"""
from hashlib import sha256


def hash256(data: str | bytes):
    # Convert hex to byte sequence
    binary = bytes.fromhex(data) if isinstance(data, str) else data

    # Hash twice
    hash1 = sha256(binary).digest()
    hash2 = sha256(hash1).digest()

    # Return hex digest
    return hash2.hex()
