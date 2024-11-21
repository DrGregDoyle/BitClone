"""
Tests for verifying schnorr signatures
"""

from secrets import randbits

from src.library.ecc import secp256k1
from src.library.hash_functions import sha256
from src.library.schnorr import schnorr_signature, verify_schnorr_signature

BIT_LENGTH = 256


def test_schnorr():
    # Setup curve
    curve = secp256k1()
    n = curve.order

    # Random private_key
    privkey = randbits(BIT_LENGTH) % n
    x, _ = curve.multiply_generator(privkey)

    # Random auxiliary bytes
    aux_rand = sha256(randbits(BIT_LENGTH)).hex

    # Random message
    message = sha256(randbits(BIT_LENGTH)).hex

    # Get schnorr signature
    sig = schnorr_signature(privkey, message, aux_rand)

    # Assert on signature verification
    assert verify_schnorr_signature(x, message, sig), "Failed to verify Schnorr signature for random data."
