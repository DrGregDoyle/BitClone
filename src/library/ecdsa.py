"""
Signature algorithms for ECDSA
"""
from secrets import randbelow

from src.library.ecc import SECP256K1


def sign_transaction(tx_id: str, private_key: int, nonce=None):
    """
    Using the private key associated with the wallet, we follow the ECDSA to sign the transaction id.

    Algorithm:
    =========
    Let E denote the elliptic curve of the wallet and let n denote the group order. As we
    are using the SECP256K1 curve, we know that n is prime. (This is a necessary condition for the ECDSA.) We
    emphasize that n IS NOT necessarily equal to the characteristic p of F_p. Let t denote the private_key.

    1) Let Z denote the integer value of the first n BITS of the transaction hash.
    2) Select a cryptographically secure random integer k in [1, n-1]. As n is prime, k will be invertible.
    3) Calculate the curve point (x,y) =  k * generator
    4) Compute r = x (mod n) and s = k^(-1)(Z + r * t) (mod n). If either r or s = 0, repeat from step 2.
    5) The signature is the pair (r, s). We choose the so-called "low s" value in the signature tuple.
    """
    # Assign known variables
    curve = SECP256K1()
    n = curve.order
    r = 0
    s = 0

    # 1 - Let Z denote the first n bits of the tx_id
    _Z = int(bin(int(tx_id, 16))[2:n + 2], 2)

    while r == 0 or s == 0:
        # 2 - Select a cryptographically secure random integer k in [1,n-1]
        k = randbelow(n - 1) if nonce is None else nonce

        # 3 - Calculate k * generator
        point = curve.generator(k)
        (x, y) = point

        # 4 - Compute r and s. If either r or s = 0 repeat from step 3
        r = x % n
        s = (pow(k, -1, n) * (_Z + r * private_key)) % n

    # Check for "low s"
    s_neg = (n - s) % n
    s = min(s, s_neg)

    # 5- Return (r,s) tuple
    return r, s


def verify_signature(signature: tuple, tx_id: str, public_key: tuple) -> bool:
    """
    Given a signature pair (r,s), an encoded message tx_id and a public key point (x,y), we verify the
    signature.

    Algorithm
    --------
    Let n denote the group order of the elliptic curve wrt the Wallet.

    1) Verify (r,s) are integers in the interval [1,n-1]
    2) Let Z be the integer value of the first n BITS of the transaction hash
    3) Let u1 = Z * s^(-1) (mod n) and u2 = r * s^(-1) (mod n)
    4) Calculate the curve point (x,y) = (u1 * generator) + (u2 * public_key)
        (where * is scalar multiplication, and + is rational point addition mod p)
    5) If r = x (mod n), the signature is valid.
    """
    curve = SECP256K1()
    # Decode signature
    r, s = signature

    # Assign known variables
    n = curve.ORDER

    # 1 - Verify (r,s)
    check_list = [1 <= r <= n - 1, 1 <= s <= n - 1]  # List will be boolean values.
    if not all(check_list):
        raise ValueError("Signature does not meet group order requirements")

    # 2 - Let Z be the first n bits of tx_id
    _Z = int(bin(int(tx_id, 16))[2:n + 2], 2)

    # 3 - Calculate u1 and u2
    s_inv = pow(s, -1, n)
    u1 = (_Z * s_inv) % n
    u2 = (r * s_inv) % n

    # 4 - Calculate the curve point
    point1 = curve.generator(u1)
    point2 = curve.scalar_multiplication(u2, public_key)
    curve_point = curve.add_points(point1, point2)

    # 5 - Return True/False based on r = x (mod n)
    if curve_point is None:
        return False
    x, _ = curve_point
    return r == x % n
