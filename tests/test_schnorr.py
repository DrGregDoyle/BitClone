"""
Tests and verifies Schnorr signatures
"""
from secrets import token_bytes, randbits

from src.core import ECC
from src.cryptography import SECP256K1, schnorr_sig, schnorr_verify

# --- CONSTANTS --- #
BYTE_LEN = ECC.COORD_BYTES
ORDER = SECP256K1.order


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

