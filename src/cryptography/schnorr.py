"""
Methods for creating a Schnorr signature and verifying
"""
from src.core import ECC, SchnorrError
from src.cryptography.ecc import SECP256K1, Point
from src.cryptography.hash_functions import schnorr_aux_hash, schnorr_challenge_hash, schnorr_nonce_hash
from src.data.ecc_keys import PubKey

#  --- CONSTANTS
BYTE_LEN = ECC.COORD_BYTES
ORDER = SECP256K1.order
PRIME = SECP256K1.p

__all__ = ["schnorr_sig", "schnorr_verify"]


def schnorr_sig(priv_key: int, msg: bytes, aux_bytes: bytes = None) -> bytes:
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

    Returns
    -------
   Returns:
        64-byte signature (r || s)

    Algorithm (BIP-340)
    -------------------
    Notation:
    - bytes32(x): 32-byte big-endian encoding of integer x
    - || : byte concatenation
    - tagged_hash(T, M): SHA256(SHA256(T) || SHA256(T) || M)
    - d: secret key, n: curve order, G: generator

    1) Public key (even-Y, x-only):
       Compute P = d·G. If y(P) is odd, set d' = n − d; else d' = d. Use x(P) as the x-only pubkey.

    2) Deterministic nonce from aux randomness:
       aux_hash = tagged_hash("BIP0340/aux", aux_rand)  # 32 bytes
       t = bytes32(d') XOR aux_hash
       k0 = int(tagged_hash("BIP0340/nonce", t || bytes32(x(P)) || msg)) mod n
       If k0 == 0, abort and use different aux_rand.

    3) Nonce point with even-Y:
       R = k0·G. If y(R) is odd, set k = n − k0 (so R flips to even-Y); else k = k0.
       Let r = x(R).

    4) Challenge:
       e = int(tagged_hash("BIP0340/challenge", bytes32(r) || bytes32(x(P)) || msg)) mod n.

    5) Signature scalar:
       s = (k + e·d') mod n.

    6) Output:
       Signature = bytes32(r) || bytes32(s)  # 64 bytes.
    """
    # Setup
    n = ORDER
    curve = SECP256K1
    aux_bytes = b'\x00' * BYTE_LEN if aux_bytes is None else aux_bytes  # Default BIP340 Array

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

    # 1. Calculate the public key and ensure an even y-coordinate
    schnorr_pubkey = curve.multiply_generator(priv_key)
    if schnorr_pubkey.y % 2 != 0:
        # If private key yields odd y, we negate the private key for use in the algorithm
        priv_key = n - priv_key
    schnorr_xbytes = schnorr_pubkey.x.to_bytes(BYTE_LEN, "big")

    # 2. Compute deterministic (private) nonce
    while True:
        aux_hash = schnorr_aux_hash(aux_bytes)
        temp_entropy = priv_key ^ int.from_bytes(aux_hash, "big")  # XOR
        k_prime = int.from_bytes(
            schnorr_nonce_hash(temp_entropy.to_bytes(BYTE_LEN, "big")) + schnorr_xbytes + msg, "big") % n
        if k_prime == 0:
            continue
        break

    # 3. Calculate public nonce
    public_nonce = curve.multiply_generator(k_prime)
    if public_nonce.y % 2 == 0:
        k_prime = n - k_prime

    # 4. Calculate challenge
    challenge_hash = schnorr_challenge_hash(public_nonce.x.to_bytes(BYTE_LEN, "big") + schnorr_xbytes + msg)
    challenge = int.from_bytes(challenge_hash, "big") % n

    # 5. Construct signature
    r = public_nonce.x
    s = (k_prime + challenge * priv_key) % n

    # Return 64 byte signature
    return r.to_bytes(BYTE_LEN, "big") + s.to_bytes(BYTE_LEN, "big")


def schnorr_verify(xonly_pubkey: int | bytes, msg: bytes, sig: bytes) -> bool:
    """
    Verifies a BIP-340 Schnorr signature (x-only, secp256k1).

    Parameters
    ----------
    xonly_pubkey : int | bytes
        x(P): the x-only public key (even-Y representative).
    msg : bytes
        The message that was signed (arbitrary length per BIP-340).
    sig : bytes
        64-byte signature: bytes32(r) || bytes32(s)

    Returns
    -------
    bool
        True if the signature is valid, otherwise False.

    Algorithm (BIP-340) — verification
    ----------------------------------
    Notation:
    - bytes32(x): 32-byte big-endian encoding of integer x
    - || : byte concatenation
    - tagged_hash(T, M): SHA256(SHA256(T) || SHA256(T) || M)
    - n: curve order, p: field prime, G: generator
    - Inputs: x(P), msg, sig = bytes32(r) || bytes32(s)

    0) Parse & range-check
       Split sig into r, s. Require 0 ≤ r < p, 0 ≤ s < n, and len(sig) == 64.

    1) Recover P from x(P)
       Reconstruct the unique curve point P with x-coordinate x(P) and even y.
       Reject if x(P) is not on the curve.

    2) Challenge
       e = int(tagged_hash("BIP0340/challenge",
                           bytes32(r) || bytes32(x(P)) || msg)) mod n.

    3) Recompute nonce point
       R' = s·G − e·P  (equivalently s·G + ((−e) mod n)·P).

    4) Checks
       Reject if R' is the point at infinity or if y(R') is odd.

    5) Decision
       Accept iff x(R') == r; otherwise reject.

    Implementation notes (correctness & efficiency)
    -----------------------------------------------
    - Include the explicit r and s range checks before any group operations.
    - Enforce even-Y on R' (reject if y(R') is odd), as required by BIP-340.
    - Use a combined multi-scalar multiplication (e.g., Straus/Shamir) for s·G − e·P.
    - Avoid unnecessary byte/int conversions; cache bytes32(x(P)) for hashing.
    """

    # Setup
    n = ORDER
    p = PRIME
    curve = SECP256K1
    pubkey_x = xonly_pubkey if isinstance(xonly_pubkey, int) else int.from_bytes(xonly_pubkey, "big")

    # --- INPUT VALIDATION --- #
    # Signature length
    if len(sig) != 2 * BYTE_LEN:
        raise SchnorrError(f"Attached signature not {2 * BYTE_LEN} bytes.")
    # Signature values
    r_bytes, s_bytes = sig[:32], sig[32:]
    r, s = int.from_bytes(r_bytes, "big"), int.from_bytes(s_bytes, "big")
    if r > p or s > n or r < 0 or s < 0:
        raise SchnorrError("Signature coordinates out of bounds")
    # Message length
    if len(msg) != BYTE_LEN:
        raise SchnorrError(f"Message to sign must be exactly {BYTE_LEN} bytes")
    # X coord on curve
    if not curve.is_x_on_curve(pubkey_x):
        raise SchnorrError("Given public key x coordinate not on curve")

    # --- MAIN ALGORITHM --- #
    # 1. Find the public key point
    y = curve.find_y_from_x(pubkey_x)
    if y % 2 != 0:
        y = p - y
    pubkey = Point(pubkey_x, y)

    # 2. Calculate the challenge
    challenge_hash = schnorr_challenge_hash(r_bytes + pubkey.x.to_bytes(BYTE_LEN, "big") + msg)
    challenge = int.from_bytes(challenge_hash, "big") % n

    # 3. Verify signature
    # pt 1 = G^s
    pt1 = curve.multiply_generator(s)
    # pt 2 = (n - e) * p
    pt2 = curve.scalar_multiplication((n - challenge), pubkey)
    # pt 3 = pt 1 + pt 2
    pt3 = curve.add_points(pt1, pt2)

    return pt3.x == r


# --- TESTING --- #
if __name__ == "__main__":
    _priv_key = 0xb7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef
    _pubkey = PubKey(_priv_key, is_even_y=True)  # Take even y coordinate for BIP0340
    print(f"XONLY PUBKEY: {_pubkey.serial_xonly().hex()}")

    # for x in range(100, 150):
    #     temp_priv_key = x
    #     msg = bytes.fromhex('deadbeef' * 8)
    #     schnorr_sig(temp_priv_key, msg)
    #     print(f'--- Test {x + 1} ---', end='\n')
