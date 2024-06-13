"""
A file for testing the Wallet and WalletFactory classes
"""
# --- IMPORTS --- #
from src.wallet import WalletFactory, Wallet


# --- TESTS --- #

def test_recovery_phrase():
    test_wallet = Wallet()
    wf = WalletFactory()

    recovery_wallet = wf.recover_wallet(
        test_wallet.seed_phrase
    )
    assert recovery_wallet._seed == test_wallet._seed
    assert recovery_wallet.pk_point == test_wallet.pk_point
