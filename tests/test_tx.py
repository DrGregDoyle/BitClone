"""
A file for testing Transaction and its related classes. Both decoding and encoding
"""
# --- IMPORTS --- #
from random import randint

from src.transaction import Input, decode_input, Output, decode_output
from src.utility import random_hash160, hash256
from src.wallet import WalletFactory


# --- TESTS --- #
# Input
# Output
# WitnessItem
# Witness
# Transaction

def test_tx_input():
    random_tx_id = hash256(random_hash160())
    random_int = randint(1, 100)
    test_wallet = WalletFactory().new_wallet()
    test_sig = test_wallet.sign_transaction(random_tx_id)

    test_input = Input(tx_id=random_tx_id, v_out=random_int, script_sig=test_sig)
    constructed_input = decode_input(test_input.encoded)
    assert constructed_input.encoded == test_input.encoded


def test_tx_output():
    random_tx_id = hash256(random_hash160())
    random_int = randint(1, 100)
    test_output = Output(amount=random_int, output_script=random_tx_id)
    constructed_output = decode_output(test_output.encoded)
    assert constructed_output.encoded == test_output.encoded
