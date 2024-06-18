"""
A file for testing the Wallet and WalletFactory classes
"""

# --- IMPORTS --- #
from secrets import randbelow

from src.wallet import WalletFactory, Wallet
from src.word_list import WORDLIST


# --- TESTS --- #

def test_recovery_phrase():
    # Verify recovery works
    test_wallet = Wallet()
    wf = WalletFactory()

    recovery_wallet = wf.recover_wallet(
        test_wallet.seed_phrase
    )
    assert recovery_wallet._seed == test_wallet._seed
    assert recovery_wallet.pk_point == test_wallet.pk_point

    # Verify recovery fails
    phony_wallet = Wallet()
    random_index = randbelow(len(WORDLIST))
    random_word = WORDLIST[random_index]
    phony_seed_phrase = phony_wallet.seed_phrase
    phony_seed_phrase[-1] = random_word

    phony_recovery_wallet = wf.recover_wallet(phony_seed_phrase)
    assert phony_recovery_wallet is None
