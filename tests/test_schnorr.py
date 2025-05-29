"""
Tests for verifying schnorr signatures
"""

from secrets import randbits

from src.crypto import hash_function, HashType, schnorr_signature, verify_schnorr_signature, ORDER, generator_exponent

BIT_LENGTH = 256
HASHTYPE = HashType.SHA256


def test_schnorr():
    # Setup curve
    # curve = secp256k1()
    n = ORDER

    def random_bytes():
        random_num = randbits(BIT_LENGTH)
        return random_num.to_bytes(length=(BIT_LENGTH + 7) // 8, byteorder="big")

    # Random private_key
    privkey = randbits(BIT_LENGTH) % n
    x, _ = generator_exponent(privkey)

    # Random auxiliary bytes
    aux_bytes = random_bytes()
    aux_rand = hash_function(encoded_data=aux_bytes, function_type=HASHTYPE)

    # Random message
    message_bytes = random_bytes()
    message = hash_function(encoded_data=message_bytes, function_type=HASHTYPE)

    # Get schnorr signature
    sig = schnorr_signature(privkey, message, aux_rand)

    # Assert on signature verification
    assert verify_schnorr_signature(x, message, sig), "Failed to verify Schnorr signature for random data."
