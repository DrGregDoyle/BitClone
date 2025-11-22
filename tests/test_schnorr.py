"""
Tests and verifies Schnorr signatures
"""

from secrets import token_bytes, randbits, randbelow

from src.core import ECC
from src.cryptography import SECP256K1, schnorr_sig, schnorr_verify

# --- CONSTANTS --- #
BYTE_LEN = ECC.COORD_BYTES
ORDER = SECP256K1.order
PRIME = SECP256K1.p


# --- HELPERS --- #
def _rand_priv():
    d = 0
    while d == 0:
        d = randbits(ECC.COORD_BYTES * 8) % ORDER
    return d


def _flip_one_bit(b: bytes) -> bytes:
    """Return a copy of b with exactly one random bit flipped (length preserved)."""
    if not b:
        raise ValueError("cannot flip a bit in empty bytes")
    bit = randbelow(len(b) * 8)
    byte_i, bit_i = divmod(bit, 8)
    ba = bytearray(b)
    ba[byte_i] ^= 1 << bit_i
    return bytes(ba)


def test_schnorr_sig():
    # Generate random message
    random_msg = token_bytes(BYTE_LEN)

    # Generate nonzero random priv_key
    priv_key = 0
    while priv_key == 0:
        priv_key = randbits(BYTE_LEN * 8) % ORDER

    # Get corresponding pubkey for verification
    pubkey = SECP256K1.multiply_generator(priv_key)

    # Generate random auxiliary bytes
    aux_rand = token_bytes(BYTE_LEN)

    # Generate Schnorr sig
    ssig = schnorr_sig(priv_key, random_msg, aux_rand)

    # Verify
    assert schnorr_verify(pubkey.x, random_msg, ssig), "Failed to verify Schnorr Signature for random data"


def test_deterministic_given_same_aux():
    d = _rand_priv()
    P = SECP256K1.multiply_generator(d)
    m = token_bytes(ECC.COORD_BYTES)
    aux = token_bytes(ECC.COORD_BYTES)
    sig1 = schnorr_sig(d, m, aux)
    sig2 = schnorr_sig(d, m, aux)
    assert sig1 == sig2, "Signing must be deterministic for fixed (d, m, aux)"
    assert schnorr_verify(P.x, m, sig1)


def test_different_aux_changes_signature_most_of_the_time():
    d = _rand_priv()
    P = SECP256K1.multiply_generator(d)
    m = token_bytes(ECC.COORD_BYTES)
    sig1 = schnorr_sig(d, m, token_bytes(ECC.COORD_BYTES))
    sig2 = schnorr_sig(d, m, token_bytes(ECC.COORD_BYTES))
    # Extremely unlikely to collide; if it ever does, regenerate once.
    if sig1 == sig2:
        sig2 = schnorr_sig(d, m, token_bytes(ECC.COORD_BYTES))
    assert sig1 != sig2
    assert schnorr_verify(P.x, m, sig1) and schnorr_verify(P.x, m, sig2)

# def test_message_tamper_rejects():
#     d = _rand_priv()
#     P = SECP256K1.multiply_generator(d)
#     m = token_bytes(64)  # longer message
#     aux = token_bytes(ECC.COORD_BYTES)
#     sig = schnorr_sig(d, m, aux)
#     m_bad = _flip_one_bit(m)
#     assert schnorr_verify(P.x, m, sig)
#     assert not schnorr_verify(P.x, m_bad, sig), "Tampered message must fail"
#
#
# def test_signature_tamper_rejects():
#     d = _rand_priv()
#     P = SECP256K1.multiply_generator(d)
#     m = token_bytes(16)
#     aux = token_bytes(ECC.COORD_BYTES)
#     sig = schnorr_sig(d, m, aux)
#     # Flip a bit in r half
#     sig_r_bad = _flip_one_bit(sig[:32]) + sig[32:]
#     # Flip a bit in s half
#     sig_s_bad = sig[:32] + _flip_one_bit(sig[32:])
#     assert schnorr_verify(P.x, m, sig)
#     assert not schnorr_verify(P.x, m, sig_r_bad)
#     assert not schnorr_verify(P.x, m, sig_s_bad)
#
#
# def test_signature_length_checks():
#     d = _rand_priv()
#     P = SECP256K1.multiply_generator(d)
#     m = token_bytes(8)
#     aux = token_bytes(BYTE_LEN)
#     sig = schnorr_sig(d, m, aux)
#     with pytest.raises(ValueError):
#         schnorr_verify(P.x, m, sig[:-1])  # 63 bytes
#     with pytest.raises(ValueError):
#         schnorr_verify(P.x, m, sig + b"\x00")  # 65 bytes
#
#
# def test_range_checks_for_r_and_s():
#     d = _rand_priv()
#     P = SECP256K1.multiply_generator(d)
#     m = token_bytes(32)
#     aux = token_bytes(ECC.COORD_BYTES)
#     sig = schnorr_sig(d, m, aux)
#     r = bytearray(sig[:32])
#     s = bytearray(sig[32:])
#
#     # Force s >= n by adding n modulo 2^256 (keep it 32 bytes)
#     n_bytes = ORDER.to_bytes(32, "big")
#     s_bad = (int.from_bytes(s, "big") + ORDER).to_bytes(32, "big")
#     with pytest.raises(ValueError):
#         schnorr_verify(P.x, m, bytes(r) + s_bad)
#
#     # If PRIME is exposed, also test r >= p
#     if PRIME is not None:
#         r_bad = PRIME.to_bytes(32, "big")  # r == p (out of range)
#         with pytest.raises(ValueError):
#             schnorr_verify(P.x, m, r_bad + bytes(s))
#
#
# def test_empty_and_long_messages():
#     d = _rand_priv()
#     P = SECP256K1.multiply_generator(d)
#     aux = token_bytes(ECC.COORD_BYTES)
#
#     for msg in (b"", token_bytes(1), token_bytes(1024)):
#         sig = schnorr_sig(d, msg, aux)
#         assert schnorr_verify(P.x, msg, sig)
#
#
# def test_wrong_public_key_rejects():
#     d1 = _rand_priv()
#     d2 = _rand_priv()
#     P1 = SECP256K1.multiply_generator(d1)
#     P2 = SECP256K1.multiply_generator(d2)
#     m = token_bytes(48)
#     aux = token_bytes(ECC.COORD_BYTES)
#     sig = schnorr_sig(d1, m, aux)
#     assert schnorr_verify(P1.x, m, sig)
#     assert not schnorr_verify(P2.x, m, sig), "Must fail under unrelated pubkey"
