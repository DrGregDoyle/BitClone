"""
A file for testing the Wallet and WalletFactory classes
"""

# --- IMPORTS --- #
from src.wallet import Wallet


# --- TESTS --- #

def test_seed_phrase():
    random_wallet = Wallet()
    seed_phrase = random_wallet.seed_phrase
    recovered_wallet = Wallet(seed_phrase)
    assert random_wallet.private_key == recovered_wallet.private_key
    assert random_wallet._seed == recovered_wallet._seed
