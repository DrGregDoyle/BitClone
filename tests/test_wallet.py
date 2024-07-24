"""
A file for testing the Wallet and WalletFactory classes
"""

from src.cipher import decode_base58check, encode_base58check
# --- IMPORTS --- #
from src.wallet import Wallet
from tests.utility import random_hex, random_base58check


# --- TESTS --- #

def test_seed_phrase():
    random_wallet = Wallet()
    seed_phrase = random_wallet.seed_phrase
    recovered_wallet = Wallet(seed_phrase)
    assert random_wallet.private_key == recovered_wallet.private_key
    assert random_wallet._seed == recovered_wallet._seed


def test_base58():
    # Test encoding/decoding
    random_data = random_hex()
    _encoded = encode_base58check(random_data)
    _decoded = decode_base58check(_encoded)
    assert _decoded == random_data

    # Test decoding/encoding
    _base58address = random_base58check()
    _decoded2 = decode_base58check(_base58address)
    _encoded2 = encode_base58check(_decoded2)
    assert _encoded2 == _base58address
