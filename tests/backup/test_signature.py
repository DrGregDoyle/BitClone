"""
We test signature DER encoding and decoding
"""
from secrets import randbits

from src.backup.signature import sign_transaction, verify_signature, encode_signature, decode_signature
from src.backup.library.ecc import SECP256K1
from tests.backup.utility import random_txid


def test_der_encoding():
    tx_id = random_txid()
    random_private_key = randbits(256)  # 256 bit random integer
    random_public_key = SECP256K1().generator(random_private_key)

    # Signature
    sig = sign_transaction(tx_id, random_private_key)  # (r,s) tuple
    encoded_sig = encode_signature(sig).hex()

    # Verify
    assert verify_signature(sig, tx_id, random_public_key)
    assert decode_signature(encoded_sig) == sig
