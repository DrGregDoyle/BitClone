"""
ECDSA algorithm.

Fixed to run on secp256k1 elliptic curve.

"""

import logging
import secrets

from src.library.ecc import secp256k1
from src.logger import get_logger

logger = get_logger(__name__)


def ecdsa(private_key: int, message: str):
    """
    Generates an ECDSA signature for a given private_key and hex_string on the specified curve.

    Parameters:
    ----------
    private_key : int
        The signer's private key.
    message : str
        The message in hex format that will be signed.

    Returns:
    --------
    tuple
        The ECDSA signature (r, s).

    Algorithm:
    ----------
    1) Initialize curve parameters and group order n.
    2) Compute z as the integer value of the first n bits of hex_string.
    3) Select a random integer k in [1, n-1].
    4) Calculate curve point (x, y) = k * generator.
    5) Compute r = x (mod n) and s = k^(-1)(Z + r * private_key) (mod n).
    6) If r or s is 0, repeat from step 3.
    7) Return the signature (r, s).

    """
    # Clean and verify message
    message = message.strip().lower()
    if message.startswith("0x"):
        message = message[2:]
    if not all(char in "0123456789abcdef" for char in message):
        raise ValueError(f"Message must be in hexadecimal format")

    # 1) Create elliptic curve object and assign n
    curve = secp256k1()
    n = curve.order

    # 2) Take the first n bits of the message using a binary mask
    z = int(message, 16) & ((1 << n.bit_length()) - 1)

    # 3 ) Generate the signature
    r, s = None, None
    while True:
        # Select a random k in [1, n-1]
        k = secrets.randbelow(n)
        if k == 0:
            continue  # Ensure k is non-zero and invertible

        # 4) Calculate the curve point (x, y) = k * generator
        x, y = curve.multiply_generator(k)

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

    # -- DEBUG: Verify signature
    if logger.level == logging.DEBUG:
        logger.debug("Verifying ECDSA")
        public_key = curve.multiply_generator(private_key)
        signed = verify_ecdsa(signature=(r, s), message=message, public_key=public_key)
        assert signed, logger.error("Failed to verify ECDSA")
        logger.debug("ECDSA has been successfully verified.")

    # 6) Return the signature (r,s)
    return r, s


def verify_ecdsa(signature: tuple, message: str, public_key: tuple) -> bool:
    """
    We verify that the given signature corresponds to the correct public_key for the given hex_string.

    Parameters
    ----------
    signature : tuple
        The signature (r, s) to verify.
    message : str
        The message that was signed, in hex format.
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
    curve = secp256k1()
    n = curve.order

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
    z = int(message, 16) & ((1 << n.bit_length()) - 1)

    # 3) Calculate u1 and u2
    s_inv = pow(s, -1, n)
    u1 = (z * s_inv) % n
    u2 = (r * s_inv) % n

    # 4) Calculate the point
    p1 = curve.multiply_generator(u1)
    p2 = curve.scalar_multiplication(u2, public_key)
    point = curve.add_points(p1, p2)

    # 5) Check if r matches x (mod n), and handle point at infinity
    if point is None:
        logger.error("Point at infinity encountered during signature verification.")
        return False

    x, _ = point
    return r == x % n
