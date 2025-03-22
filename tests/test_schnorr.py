"""
Tests for verifying schnorr signatures
"""

from secrets import randbits

from src.crypto.ecc import secp256k1
from src.crypto.hash_functions import hash_function, HashType
from src.crypto.schnorr import schnorr_signature, verify_schnorr_signature

BIT_LENGTH = 256
HASHTYPE = HashType.SHA256


def test_schnorr():
    # Setup curve
    curve = secp256k1()
    n = curve.order

    def random_bytes():
        random_num = randbits(BIT_LENGTH)
        return random_num.to_bytes(length=(BIT_LENGTH + 7) // 8, byteorder="big")

    # Random private_key
    privkey = randbits(BIT_LENGTH) % n
    x, _ = curve.multiply_generator(privkey)

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
