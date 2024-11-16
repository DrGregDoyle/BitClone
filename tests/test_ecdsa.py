"""
The generate signature has a verification method in it, so we need only sign a transaction
"""
from secrets import randbits

from src.library.ecc import secp256k1
from src.library.ecdsa import ecdsa, verify_ecdsa

BIT_LENGTH = 256


def test_ecdsa():
    # Standard curve
    curve = secp256k1()

    # Random 256-bit private key
    private_key = randbits(BIT_LENGTH)
    public_key = curve.multiply_generator(private_key)

    # Message is 256-bit hex string
    message = hex(randbits(BIT_LENGTH))

    signature = ecdsa(private_key, message)

    verification = verify_ecdsa(signature, message, public_key)
    assert verification, "Failed to verify ECDSA."
