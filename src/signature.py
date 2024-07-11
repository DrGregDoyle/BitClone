"""
Signature
"""
from secrets import randbelow

from src.library.ecc import SECP256K1
from src.predicates import Endian


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


def encode_signature(sig: tuple, sighash=None) -> bytes:
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
    cs_header = bytes.fromhex("30")
    int_header = bytes.fromhex("02")

    # Get integer values of signature
    r, s = sig

    # Format r
    hex_r = r.to_bytes(length=32, byteorder="big").hex()
    binary_r = format(r, "0256b")  # 256 bits
    if binary_r[0] == "1":
        # Signed int - prepend byte
        hex_r = "00" + hex_r
    byte_r = bytes.fromhex(hex_r)
    byte_encoded_r = int_header + len(byte_r).to_bytes(length=1, byteorder="big") + byte_r

    # Format s
    hex_s = s.to_bytes(length=32, byteorder="big").hex()
    binary_s = format(s, "0256b")
    if binary_s[0] == "1":
        hex_s = "00" + hex_s
    byte_s = bytes.fromhex(hex_s)
    byte_encoded_s = int_header + len(byte_s).to_bytes(length=1, byteorder="big") + byte_s

    # Format DER
    der_length = len(byte_encoded_r + byte_encoded_s)  # Byte length

    # Add sighash
    _sighash = 1 if sighash is None else sighash
    sighash_bytes = Endian(_sighash, byte_size=1).bytes

    # Return bytes
    return cs_header + der_length.to_bytes(length=1, byteorder="big") + byte_encoded_r + byte_encoded_s + sighash_bytes


def decode_signature(der_encoded: str | bytes):
    # get data as hex string
    der_encoded = der_encoded.hex() if isinstance(der_encoded, bytes) else der_encoded

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


def scriptpubkey_p2pk(public_key: str):
    # OP_CHECKSIG: 0xac
    # OP_PUSHDATA_n: hex(n), n<=74
    op_checksig = "ac"
    push_data_code = format(len(public_key) // 2, "02x")
    return push_data_code + public_key + op_checksig


def scriptsig_p2pk(signature: str):
    push_data_code = format(len(signature) // 2, "02x")
    return push_data_code + signature

# --- TESTING
# from src.wallet import HDWallet, ExtendedPrivateKey
# from src.library.ecc import SECP256K1
#
# if __name__ == "__main__":
#     w = HDWallet()
#     xpriv = ExtendedPrivateKey(w.keys.get("receiving"))
#     xpriv.new_private_child()
#     xpriv.new_public_child()
#     public_key = xpriv.get_public_child(0)
#     private_key = xpriv.get_private_child(ExtendedPrivateKey.HARDENED_INDEX)
#     print(xpriv.child_priv)
#     print(xpriv.child_pub)
#
#     # print(f"PUBLIC KEY: {public_key}")
#     # print(f"ACTUAL PUBLIC KEY: {public_key[:66]}")
#     # print(f"PRIVATE KEY: {private_key}")
#     # print(f"ACTUAL PRIVATE KEY: {private_key[:64]}")
#     # pk_int = int(private_key[:64], 16)
#     # pk_pt = decompress_point(public_key[:66])
#     # print(f"PUBLIC KEY POINT: {pk_pt}")
#     #
#     # tx = random_tx()
#     # print(f"TXID: {tx.txid}")
#     # sig = sign_transaction(tx.txid, pk_int)
#     # encoded_sig = encode_signature(sig)
#     # scriptsig = scriptsig_p2pk(encoded_sig.hex())
#     #
#     # curve = SECP256K1()
#     # recovered_pt = curve.generator(pk_int)
#     # print(f"PUBLIC KEY POINT FROM PK_INT: {recovered_pt}")
