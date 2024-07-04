"""
A module for cryptographic elements related to BitCoin
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


def reverse_bytes(data: str | bytes):
    # Get data as hex string
    hex_data = data.hex() if isinstance(data, bytes) else data

    # Return string reversed every 2 characters (bytes reversed)
    return "".join([hex_data[i:i + 2] for i in reversed(range(0, len(hex_data), 2))])


if __name__ == "__main__":
    pass
