"""
A file for testing the Wallet and WalletFactory classes
"""
# --- IMPORTS --- #
from src.wallet import WalletFactory, Wallet


# --- TESTS --- #

def test_recovery_phrase():
    test_wallet = Wallet()
    wf = WalletFactory()

    recovery_seed = wf.recover_wallet(
        test_wallet.seed_phrase
    )
    assert recovery_seed == test_wallet._seed
