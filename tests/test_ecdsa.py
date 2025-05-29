"""
The generate signature has a verification method in it, so we need only sign a transaction
"""
from secrets import randbits, token_bytes

from src.crypto import ecdsa, verify_ecdsa, generator_exponent

BIT_LENGTH = 256


def test_ecdsa():
    # Random 256-bit private key
    private_key = randbits(BIT_LENGTH)
    public_key = generator_exponent(private_key)

    # Message = 32 random bytes
    message = token_bytes(32)

    signature = ecdsa(private_key, message)

    verification = verify_ecdsa(signature, message, public_key)
    assert verification, "Failed to verify ECDSA."
