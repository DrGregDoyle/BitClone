"""
Methods to create and verify a signature created using ECDSA
"""
import secrets
from typing import Tuple

from src.core.exceptions import ECDSAError
from src.cryptography.ecc import SECP256K1, Point

__all__ = ["ecdsa", "verify_ecdsa"]

curve = SECP256K1


def ecdsa(private_key: int, message: bytes) -> Tuple[int, int]:
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
    # 1. Get order from given elliptic curve
    n = curve.order

    # 2. Keep the n leftmost bits of the message
    z = int.from_bytes(message, 'big')
    excess = len(message) * 8 - n.bit_length()
    if excess > 0:
        z >>= excess

    # 3. Generate the signature
    r, s = None, None
    while True:
        # Select a random k in [1,n-1]
        while True:
            k = secrets.randbelow(n)
            if k != 0:  # Suitable random number found
                break

        # 4. Calculate the curve point g^k
        x, y = curve.multiply_generator(k)

        # 5. Compute r and s | Return to step 3 if either of r, s is zero
        r = x % n
        if r == 0:
            continue

        # Compute s = k^(-1) * (z + r * private_key) mod n
        s = (pow(k, -1, n) * (z + r * private_key)) % n
        if s == 0:
            continue

        # valid signature found, exit loop
        break

    # 6. Return smaller s value
    if s > n // 2:
        s = n - s

    # 7. Return signature
    return r, s


def verify_ecdsa(signature: tuple, message: bytes, public_key: Point | tuple) -> bool:
    """
    We verify that the given signature corresponds to the correct public_key for the given hex_string.

    Parameters
    ----------
    signature : tuple
        The signature (r, s) to verify.
    message : bytes
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
    # Setup
    n = curve.order
    r, s = signature

    # 1. Verify r,s are in [1,n-1]
    if not (1 <= r < n):
        raise ECDSAError(f"ECDSA r value {r} out of bounds.")
    if not (1 <= s < n):
        raise ECDSAError(f"ECDSA s value {s} out of bounds.")

    # 2. Take the leftmost n bits of the message
    z = int.from_bytes(message, 'big')
    excess = len(message) * 8 - n.bit_length()
    if excess > 0:
        z >>= excess

    # 3. Calculate u1 and u2
    s_inv = pow(s, -1, n)
    u1 = (z * s_inv) % n
    u2 = (r * s_inv) % n

    # 4. Calculate the point
    pt1 = curve.multiply_generator(u1)
    pt2 = curve.scalar_multiplication(u2, public_key)
    final_pt = curve.add_points(pt1, pt2)

    # 5. Signature is valid if r == final_point.x (mod n)
    return r == final_pt.x % n


# --- TESTING ---
if __name__ == "__main__":
    generator_pt = SECP256K1.generator
    test_message_1 = bytes.fromhex("deadbeef")
    test_message_2 = bytes.fromhex("deadbeef" * 64)

    sig1 = ecdsa(1, test_message_1)
    sig2 = ecdsa(1, test_message_2)

    print(f"SIGNATURE 1: {sig1}")
    print(f"SIGNATURE 2: {sig2}")

    check1 = verify_ecdsa(sig1, test_message_1, generator_pt)
    check2 = verify_ecdsa(sig2, test_message_2, generator_pt)

    print(f"SIGNATURE 1 VERIFIED: {check1}")
    print(f"SIGNATURE 2 VERIFIED: {check2}")
