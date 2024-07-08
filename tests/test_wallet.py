"""
A file for testing the Wallet and WalletFactory classes
"""

# --- IMPORTS --- #
from src.wallet import HDWallet


# --- TESTS --- #

def test_seed_phrase():
    random_wallet = HDWallet()
    seed_phrase = random_wallet.seed_phrase
    recovered_wallet = HDWallet(seed_phrase)
    assert random_wallet.keys["master"] == recovered_wallet.keys["master"]

# def test_signature():
#     tx_id = random_txid()
#     test_wallet = HDWallet()
#     test_xpriv = ExtendedPrivateKey(test_wallet.keys["master"])
#     xpriv_int = int(test_xpriv.priv, 16)
#     xpub_pt = test_xpriv.get_pt(test_xpriv.pub)
#
#     sig = test_wallet.sign_transaction(tx_id, xpriv_int)
#     assert test_wallet.verify_signature(sig, tx_id, xpub_pt)
