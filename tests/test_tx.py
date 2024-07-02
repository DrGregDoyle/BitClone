"""
A file for testing Transaction and its related classes. Both decoding and encoding
"""
# --- IMPORTS --- #

from src.decoder_lib import decode_witness_item
from tests.utility import random_witness_item


# --- TESTS --- #


# def test_tx_input():
#     test_input = random_input()
#     constructed_input = decode_input(test_input.encoded)
#     assert constructed_input.encoded == test_input.encoded
#
#
# def test_tx_output():
#     test_output = random_output()
#     constructed_output = decode_output(test_output.encoded)
#     assert constructed_output.encoded == test_output.encoded


def test_witness_item():
    test_wi = random_witness_item()
    print(f"RANDOM WITNESS ITEM")
    print(f"JSON: {test_wi.to_json()}")
    print(f"DISPLAY: {test_wi.display}")
    print(f"ENCODED: {test_wi.encoded}")
    constructed_wi = decode_witness_item(test_wi.display)

    # assert constructed_wi.display == test_wi.display

# def test_witness():
#     test_witness = random_witness()
#     constructed_witness = decode_witness(test_witness.encoded)
#     assert constructed_witness.encoded == test_witness.encoded
#
#
# def test_transaction():
#     test_tx = random_tx()
#     print(f"TEST TX: {test_tx.to_json()}")
#     constructed_tx = decode_tx(test_tx.encoded)
#     assert constructed_tx.encoded == test_tx.encoded
