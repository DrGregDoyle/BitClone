"""
We test signature DER encoding and decoding
"""
from secrets import randbits

from src.cryptography import SECP256K1
from src.signature import sign_transaction, verify_signature, encode_signature, decode_signature
from tests.utility import random_tx_id


def test_der_encoding():
    tx_id = random_tx_id()
    random_private_key = randbits(256)  # 256 bit random integer
    random_public_key = SECP256K1().generator(random_private_key)

    # Signature
    sig = sign_transaction(tx_id, random_private_key)  # (r,s) tuple
    encoded_sig = encode_signature(sig)

    # Verify
    assert verify_signature(sig, tx_id, random_public_key)
    assert decode_signature(encoded_sig) == sig
