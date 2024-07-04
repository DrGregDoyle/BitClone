"""
Signature
"""
from secrets import randbelow

from src.library.cryptography import SECP256K1


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
    5) The signature is the pair (r, s), formatted to hex_r + hex_s.
    """
    # Assign known variables
    curve = SECP256K1()
    n = curve.order
    r = 0
    s = 0

    # 1 - Let Z denote the first n bits of the tx_id
    Z = int(format(int(tx_id, 16), "b")[:n], 2)

    while r == 0 or s == 0:
        # 2 - Select a cryptographically secure random integer k in [1,n-1]
        k = randbelow(n - 1) if nonce is None else nonce

        # 3 - Calculate k * generator
        point = curve.generator(k)
        # point = self.CURVE.scalar_multiplication(k, self.CURVE.g)
        (x, y) = point

        # 4 - Compute r and s. If either r or s = 0 repeat from step 3
        r = x % n
        s = (pow(k, -1, n) * (Z + r * private_key)) % n

    # Check for "low s"
    s_neg = (n - s) % n

    s = min(s, s_neg)

    # 5- Return (r,s) tuple
    return (r, s)


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
    Z = int(format(int(tx_id, 16), "b")[:n], 2)

    # 3 - Calculate u1 and u2
    s_inv = pow(s, -1, n)
    u1 = (Z * s_inv) % n
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


def encode_signature(sig: tuple, sighash_type=None):
    """
    via Pieter Wuille:
        A correct DER-encoded signature has the following form:

        0x30: a header byte indicating a compound structure.
        A 1-byte length descriptor for all what follows.
        0x02: a header byte indicating an integer.
        A 1-byte length descriptor for the R value
        The R coordinate, as a big-endian integer.
        0x02: a header byte indicating an integer.
        A 1-byte length descriptor for the S value.
        The S coordinate, as a big-endian integer.
    """
    # Headers
    cs_header = 0x30
    int_header = 0x02

    # Get integer values of signature
    r, s = sig

    # Format r
    hex_r = format(r, "064x")  # 32 bytes
    binary_r = format(r, "0256b")  # 256 bits
    if binary_r[0] == "1":
        # Signed int - prepend byte
        hex_r = "00" + hex_r
    length_r = len(hex_r) // 2  # Byte length of 32 or 33
    encoded_r = format(int_header, "02x") + format(length_r, "02x") + hex_r

    # Format s
    hex_s = format(s, "064x")
    binary_s = format(s, "0256b")
    if binary_s[0] == "1":
        hex_s = "00" + hex_s
    length_s = len(hex_s) // 2
    encoded_s = format(int_header, "02x") + format(length_s, "02x") + hex_s

    # Format DER
    der_length = len(encoded_r + encoded_s) // 2  # Byte length
    return format(cs_header, "02x") + format(der_length, "02x") + encoded_r + encoded_s


def decode_signature(der_encoded: str):
    # Config
    i = 0
    byte_chars = 2

    # Get DER values
    header = der_encoded[:i]
    i += byte_chars
    sig_length = int(der_encoded[i:i + byte_chars], 16)
    i += byte_chars

    # Get R values
    r_int_type = der_encoded[i:i + 2]
    i += byte_chars
    r_length = int(der_encoded[i:i + 2], 16)
    i += byte_chars
    r = int(der_encoded[i: i + 2 * r_length], 16)
    i += 2 * r_length

    # Get S values
    s_int_type = der_encoded[i:i + 2]
    i += byte_chars
    s_length = int(der_encoded[i:i + 2], 16)
    i += byte_chars
    s = int(der_encoded[i: i + 2 * s_length], 16)
    i += 2 * s_length

    # Get hashtype byte
    hash_type = der_encoded[i:]
    # TODO: Implement hash type

    return (r, s)


# --- TESTING
if __name__ == "__main__":
    # m = "1e3dede7449fce6a41662aa77ac9472997bffbeaf14ea59fac7150d60f7672cc"
    # k = 0x208203c62de50295437e58741bfee209870d0b0cb9baee969c344983e6e127c7
    # pk = 0x4abfeb77b628e1882a9e9af73746839a207f81763c846e42cf10bd00bf4e1694
    # pubkey = SECP256K1().generator(pk)
    # sig = sign_transaction(m, pk, k)
    # verify_signature(sig, m, pubkey)
    # der_encoded = encode_signature(sig)
    # r, s = sig
    # hex_r, hex_s = format(r, "064x"), format(s, "064x")
    # print(f'HEX RS: {hex_r, hex_s}')
    # print(f"DER ENCODING: {der_encoded}")

    test_r = 65691285541932536009248411738265789963354503151730896788560460410523233552620
    test_s = 19098175386364295391902250148711978865337848634153088378528036920821166148819
    known_encoding = "3045022100913bf333c978ba2580d993f4c1a6f4aca0ece9b0d670fa4e2cff11d0b77008ec02202a392f28199fde4e81eafbdeb1c29de29805d9b802f176cb95b983e704ec8cd3"
    constructed_encoding = encode_signature((test_r, test_s))
    constructed_tuple = decode_signature(constructed_encoding)
    print(f"DECODING GIVES BACK CORRECT (R,S) VALUES: {constructed_tuple == (test_r, test_s)}")
    # print(f"ORIGINAL R: {test_r}")
    # print(f"ORIGINAL S: {test_s}")
    # # print(f"ENCODING WORKED: {known_encoding == constructed_encoding}")
    # # print(f"KNOWN ENCODING: {known_encoding}")
    # # print(f"CONSTRUCTED ENCODING: {constructed_encoding}")
