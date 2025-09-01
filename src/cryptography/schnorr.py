"""
Methods for creating a Schnorr signature and verifying
"""
from src.core import SchnorrError
from src.cryptography.ecc import EllipticCurve, secp256k1


def schnorr_sig(priv_key: int, msg: bytes, aux_rand: bytes, curve: EllipticCurve = secp256k1()) -> tuple[int, int]:
    """
    Produces a BIP-340 Schnorr signature for the given message and private key.

    Parameters
    ----------
    priv_key : int
        The signer's 32-byte secret scalar modulo the curve order n.
    msg : bytes
        The message to be signed. The function will internally hash this data
        with SHA256 in the BIP-340 challenge construction.
    aux_rand : bytes
        Optional 32-byte auxiliary randomness to protect against side-channels
        (combined with the private key as defined in BIP-340).

    Returns
    -------
    tuple[int, int]
        The Schnorr signature (r, s), each encoded as 32-byte integers.

    Algorithm (BIP-340)
    -------------------
    1) Derive the x-only public key P from the private key, ensuring an even y.
       If y is odd, negate the private key modulo n.
    2) Compute deterministic nonce k' = SHA256("BIP0340/nonce" || priv_key ||
       message || aux_rand), then set k = k' mod n. If k = 0, retry with new
       randomness.
    3) Compute the nonce point R = k·G, enforce even y by negating k if needed,
       and let r = x(R).
    4) Compute the challenge
           e = int(SHA256("BIP0340/challenge" || r || x(P) || msg)) mod n.
    5) Compute signature scalar s = (k + e·priv_key) mod n.
    6) Output the signature (r, s).

    Verification
    ------------
    Given (r, s), message m, and public key P, the verifier checks:
        R = s·G − e·P
        r == x(R) and y(R) is even
    where e is recomputed as in step 4.


    """
    # Setup
    n = curve.order

    # Error checking
    if priv_key > n:
        raise SchnorrError("Private key value exceeds curve order")

    # 1. Derive the x-only public key from the private key, negate priv_key if y odd
    x, y = curve.multiply_generator(priv_key)
    if y % 2 != 0:
        priv_key = n - priv_key
