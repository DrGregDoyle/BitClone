"""
Methods for creating a Schnorr signature and verifying
"""
from src.core import ECC, SchnorrError
from src.cryptography.ecc import EllipticCurve, SECP256K1
from src.cryptography.ecc_keys import PubKey

# # --- CONSTANTS
BYTE_LEN = ECC.COORD_BYTES


def schnorr_sig(priv_key: int, msg: bytes, aux_bytes: bytes = None, curve: EllipticCurve = SECP256K1) -> bytes:
    """
    Produces a BIP-340 Schnorr signature for the given message and private key.

    Parameters
    ----------
    priv_key : int
        The signer's 32-byte secret scalar modulo the curve order n.
    msg : bytes
        The message to be signed. The function will internally hash this data
        with SHA256 in the BIP-340 challenge construction.
    aux_bytes : bytes
        Optional 32-byte auxiliary randomness to protect against side-channels
        (combined with the private key as defined in BIP-340).
    curve: EllipticCurve
        Optionally specify the elliptic curve to be used. Defaults to secp256k1 curve.

    Returns
    -------
   Returns:
        64-byte signature (r || s)

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
    aux_bytes = b'\x00' * BYTE_LEN if aux_bytes is None else aux_bytes

    # --- Input validation -- #
    # Private key
    if not (1 <= priv_key < n):
        raise SchnorrError(f"Private key must be in range [1, {n})")
    # Message length
    if len(msg) != BYTE_LEN:
        raise SchnorrError(f"Message to sign must be exactly {BYTE_LEN} bytes")
    # Auxiliary bytes length
    if len(aux_bytes) != BYTE_LEN:
        raise SchnorrError(f"Auxiliary bytes must be exactly {BYTE_LEN} bytes")

    # --- Main algorithm --- #

    # 1. Derive the x-only public key from the private key
    schnorr_pubkey = PubKey(priv_key, is_even_y=True)
