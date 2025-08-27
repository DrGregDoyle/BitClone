"""
Helper functions for the mathematics of elliptic curves
"""

__all__ = ["is_quadratic_residue", "tonelli_shanks"]


def is_quadratic_residue(n: int, p: int) -> bool:
    """
    Returns True if (n|p) != -1. (We include 0 as quadratic residues.)
    """
    n = n % p
    if n == 0:
        return True

    criterion = pow(n, (p - 1) >> 2, p)
    return criterion != p - 1


def tonelli_shanks(n: int, p: int) -> int:
    """
    Assuming n is a quadratic residue mod p, we return an integer r such that r^2 = n (mod p).
    Optimized version with fewer modular operations and early returns.
    """
    n = n % p

    # Trivial case
    if n == 0:
        return 0

    # Verify n is a quadratic residue (optimized check)
    if pow(n, (p - 1) >> 1, p) == p - 1:
        raise ValueError("Tonelli Shanks called on quadratic non-residue")

    # p = 3 (mod 4) case - most common for cryptographic primes
    if p & 3 == 3:  # Bitwise AND instead of modulo
        return pow(n, (p + 1) >> 2, p)

    # --- GENERAL CASE --- #
    # 1) Divide p-1 into its even and odd components by p-1 = 2^s * q
    q = p - 1
    s = 0
    while (q & 1) == 0:  # Use bitwise AND instead of modulo
        s += 1
        q >>= 1  # Use bitshift instead of division

    # 2) Find a quadratic non residue (cached for common primes would be better)
    z = 2
    while pow(z, (p - 1) >> 1, p) != p - 1:
        z += 1

    # 3) Configure initial variables
    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) >> 1, p)

    # 4) Repeat until t == 1
    while t != 1:
        # Find the least integer i such that t^(2^i) = 1 (mod p)
        i = 1
        temp = (t * t) % p
        while temp != 1:
            i += 1
            temp = (temp * temp) % p

        # Reassign variables
        exp = 1 << (m - i - 1)  # Use bitshift for 2^(m-i-1)
        b = pow(c, exp, p)
        m = i
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p

    return r
