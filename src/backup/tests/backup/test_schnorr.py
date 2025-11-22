"""
Tests for verifying schnorr signatures
"""

from secrets import randbits

from src.backup.crypto import schnorr_signature, verify_schnorr_signature, ORDER, generator_exponent, sha256

BIT_LENGTH = 256


def test_schnorr():
    def random_bytes():
        random_num = randbits(BIT_LENGTH)
        return random_num.to_bytes(length=(BIT_LENGTH + 7) // 8, byteorder="big")

    # Random private_key
    privkey = randbits(BIT_LENGTH) % ORDER
    x, _ = generator_exponent(privkey)

    # Random auxiliary bytes
    aux_bytes = random_bytes()
    aux_rand = sha256(aux_bytes)

    # Random message
    message_bytes = random_bytes()
    message = sha256(message_bytes)

    # Get schnorr signature
    sig = schnorr_signature(privkey, message, aux_rand)

    # Assert on signature verification
    assert verify_schnorr_signature(x, message, sig), "Failed to verify Schnorr signature for random data."
