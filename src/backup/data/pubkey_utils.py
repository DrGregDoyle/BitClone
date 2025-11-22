"""
Used for encoding and decoding
"""
from src.backup.crypto import generator_exponent, get_y_from_x, PRIME, get_pt_from_x

PUBKEY_BYTELENGTH = 32

__all__ = ["compress_public_key", "decompress_public_key", "get_public_key_point"]


# --- ECC PUBLIC/PRIVATE KEY ENCODING --- #

def compress_public_key(*args) -> bytes:
    """
    Accepts either:
        1) A single integer, assumed to be the private key
        2) A single tuple, assumed to be the public key point
        3) Two integers, assumed to be the coordinates of the public key point
    """
    if len(args) == 1:
        # Private key
        if isinstance(args[0], int):
            x, y = generator_exponent(args[0])
        # Tuple
        elif isinstance(args[0], tuple):
            x, y = args[0]
        else:
            raise TypeError("Expected a private key or public key point")
    elif len(args) == 2:
        x, y = args
    else:
        raise TypeError("Given arguments not supported for compression")

    # Verify x and y are integers
    if not (isinstance(x, int) and isinstance(y, int)):
        raise TypeError("Tuple must contain two integers.")

    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    x_bytes = x.to_bytes(PUBKEY_BYTELENGTH, 'big')
    return prefix + x_bytes


def decompress_public_key(compressed_key: bytes) -> tuple[int, int]:
    if len(compressed_key) != 33:
        raise ValueError("Invalid compressed public key length (must be 33 bytes).")

    prefix = compressed_key[0]  # Indexed bytes return integers
    if prefix not in (0x02, 0x03):
        raise ValueError("Invalid public key prefix (must be 0x02 or 0x03).")

    # Extract x-coordinate
    x = int.from_bytes(compressed_key[1:], byteorder='big')

    # Get one possible value of y
    y1 = get_y_from_x(x)

    # Get other possible value of y
    y2 = PRIME - y1

    # Check parity of y_candidate. If it doesn't match prefix, use the other root.
    #  - prefix 0x02 => y should be even
    #  - prefix 0x03 => y should be odd
    y = y1 if (y1 & 1) == (prefix & 1) else y2

    return x, y


def get_public_key_point(pubkey: bytes) -> tuple[int, int]:
    """
    Converts a public key in various formats into an (x, y) point on the secp256k1 curve.

    Accepts:
        - 32 bytes (x-only): used in Taproot
        - 33 bytes (compressed): 1-byte prefix + 32-byte x
        - 64 bytes (x||y): raw coordinates
        - 65 bytes (uncompressed): 1-byte prefix + 32-byte x + 32-byte y
    """
    length = len(pubkey)

    if length == 32:
        x = int.from_bytes(pubkey, "big")
        return get_pt_from_x(x)  # Will have even y-coord by default

    elif length == 33:
        prefix = pubkey[0]
        if prefix not in (0x02, 0x03):
            raise ValueError("Invalid prefix for compressed pubkey")
        x = int.from_bytes(pubkey[1:], "big")
        return get_pt_from_x(x, prefix)

    elif length == 64:
        x = int.from_bytes(pubkey[:32], "big")
        y = int.from_bytes(pubkey[32:], "big")
        return x, y

    elif length == 65:
        if pubkey[0] != 0x04:
            raise ValueError("Invalid prefix for uncompressed pubkey")
        x = int.from_bytes(pubkey[1:33], "big")
        y = int.from_bytes(pubkey[33:], "big")
        return x, y

    raise ValueError("Unknown pubkey format")
