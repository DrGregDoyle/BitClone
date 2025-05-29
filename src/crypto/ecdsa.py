"""
ECDSA algorithm.

Fixed to run on secp256k1 elliptic curve.

"""

import secrets

from src.crypto.curve_utils import ORDER, generator_exponent, scalar_multiplication, add_points
from src.logger import get_logger

logger = get_logger(__name__)

__all__ = ["ecdsa", "verify_ecdsa"]


def ecdsa(private_key: int, message_hash: bytes):
    """
    Generates an ECDSA signature for a given private_key and message hash on the specified curve.

    Parameters:
    ----------
    private_key : int
        The signer's private key.
    message_hash : bytes
        The hash of the message (typically a transaction hash) that will be signed.

    Returns:
    --------
    tuple
        The ECDSA signature (r, s). (using low s as per BIP-62)

    Algorithm:
    ----------
    1) Initialize curve parameters and group order n.
    2) Compute z as the integer value of the first n bits of message hash.
    3) Select a random integer k in [1, n-1].
    4) Calculate curve point (x, y) = k * generator.
    5) Compute r = x (mod n) and s = k^(-1)(Z + r * private_key) (mod n).
    6) If r or s is 0, repeat from step 3.
    7) Return the signature (r, s).

    """
    # 1) Create elliptic curve object and assign n
    # curve = secp256k1()
    n = ORDER  # curve.order

    # 2) Take the first n bits of the message using a binary mask
    z = int.from_bytes(message_hash, byteorder='big') & ((1 << n.bit_length()) - 1)

    # 3 ) Generate the signature
    r, s = None, None
    while True:
        # Select a random k in [1, n-1]
        while True:
            k = int.from_bytes(secrets.token_bytes(32), "big")
            if 1 <= k < n:
                break

        # 4) Calculate the curve point (x, y) = k * generator
        x, y = generator_exponent(k)  # curve.multiply_generator(k)

        # 5) Compute r and s
        r = x % n
        if r == 0:
            continue  # Go to step 3 if r is 0

        # Compute s = k^(-1) * (z + r * private_key) mod n
        s = (pow(k, -1, n) * (z + r * private_key)) % n
        if s == 0:
            continue  # Go to step 3 if s is 0

        # Valid signature found, exit loop
        break

    # 6) Get low_s
    low_s = n - s
    s = min(low_s, s)

    # 7) Return the signature (r,s)
    return r, s


def verify_ecdsa(signature: tuple, message_hash: bytes, public_key: tuple) -> bool:
    """
    We verify that the given signature corresponds to the correct public_key for the given hex_string.

    Parameters
    ----------
    signature : tuple
        The signature (r, s) to verify.
    message_hash : bytes
        The hash of the message that was signed.
    public_key : tuple
        The public key used for verification.

    Returns
    -------
    bool
        True if the signature is valid, False otherwise.

    Algorithm
    --------
    Let n denote the group order of the elliptic curve.

    1) Verify that (r,s) are integers in the interval [1,n-1]
    2) Let z be the integer value of the first n bits of the transaction hash
    3) Let u1 = z * s^(-1) (mod n) and u2 = r * s^(-1) (mod n)
    4) Calculate the curve point (x,y) = (u1 * generator) + (u2 * public_key)
        (where * is scalar multiplication, and + is elliptic curve point addition mod p)
    5) If r = x (mod n), the signature is valid.
    """
    # Get elliptic curve and order
    # curve = secp256k1()
    # n = curve.order
    n = ORDER

    # Get signature values
    r, s = signature

    # 1) Verify our values first
    if not (1 <= r < n):
        logger.error(f"ECDSA r value {r} out of bounds.")
        return False
    if not (1 <= s < n):
        logger.error(f"ECDSA s value {s} out of bounds.")
        return False

    # 2) Take the first n bits of the transaction hash using a binary mask
    z = int.from_bytes(message_hash, byteorder='big') & ((1 << n.bit_length()) - 1)

    # 3) Calculate u1 and u2
    s_inv = pow(s, -1, n)
    u1 = (z * s_inv) % n
    u2 = (r * s_inv) % n

    # 4) Calculate the point
    p1 = generator_exponent(u1)  # curve.multiply_generator(u1)
    p2 = scalar_multiplication(u2, public_key)  # curve.scalar_multiplication(u2, public_key)
    point = add_points(p1, p2)  # curve.add_points(p1, p2)

    # 5) Check if r matches x (mod n), and handle point at infinity
    if point is None:
        logger.error("Point at infinity encountered during signature verification.")
        return False

    x, _ = point
    return r == x % n
