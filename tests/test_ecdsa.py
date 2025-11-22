"""
We generate random signatures and verify
"""
from secrets import token_bytes, randbelow

from src.cryptography import ecdsa, verify_ecdsa, SECP256K1


def test_ecdsa():
    # Get random message values
    msg1 = token_bytes(16)
    msg2 = token_bytes(32)
    msg3 = token_bytes(64)
    msg4 = token_bytes(128)
    msg5 = token_bytes(256)

    # Generate public and private key
    while True:
        priv_key = randbelow(SECP256K1.order)
        if priv_key != 0:
            break
    pub_key = SECP256K1.multiply_generator(priv_key)

    # Get signatures
    messages = [msg1, msg2, msg3, msg4, msg5]
    signatures = [ecdsa(priv_key, m) for m in messages]

    # Verify signature
    for x in range(len(messages)):
        temp_msg = messages[x]
        temp_sig = signatures[x]
        assert verify_ecdsa(temp_sig, temp_msg, pub_key), "Failed to verify ECDSA signature for random data"
