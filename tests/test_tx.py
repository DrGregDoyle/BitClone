"""
A file for testing Transaction and its related classes. Both decoding and encoding
"""
# --- IMPORTS --- #

from src.decoder_lib import decode_input, decode_witness_item, decode_witness, decode_tx, decode_output
from tests.utility import random_input, random_output, random_witness_item, random_witness, random_tx


# from src.utility import random_hash160, hash256
# from src.wallet import WalletFactory


# --- TESTS --- #


def test_tx_input():
    test_input = random_input()
    constructed_input = decode_input(test_input.encoded)
    assert constructed_input.encoded == test_input.encoded


def test_tx_output():
    test_output = random_output()
    constructed_output = decode_output(test_output.encoded)
    assert constructed_output.encoded == test_output.encoded


def test_witness_item():
    test_wi = random_witness_item()
    constructed_wi = decode_witness_item(test_wi.encoded)
    assert constructed_wi.encoded == test_wi.encoded


def test_witness():
    test_witness = random_witness()
    constructed_witness = decode_witness(test_witness.encoded)
    assert constructed_witness.encoded == test_witness.encoded


def test_transaction():
    test_tx = random_tx()
    constructed_tx = decode_tx(test_tx.encoded)
    assert constructed_tx.encoded == test_tx.encoded
