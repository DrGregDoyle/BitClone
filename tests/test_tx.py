"""
A file for testing Transaction and its related classes. Both decoding and encoding
"""
# --- IMPORTS --- #

from src.transaction import decode_input, decode_output, decode_witness_item, decode_witness, decode_transaction
from tests.utility import random_input, random_witness, random_witness_item, random_output, random_tx


# --- TESTS --- #


def test_tx_input():
    i = random_input()
    bytes_i = decode_input(i.bytes)
    hex_i = decode_input(i.hex)

    assert bytes_i.bytes == i.bytes
    assert hex_i.bytes == i.bytes


def test_tx_output():
    t = random_output()
    bytes_t = decode_output(t.bytes)
    hex_t = decode_output(t.hex)

    assert bytes_t.bytes == t.bytes
    assert hex_t.bytes == t.bytes


def test_witness_item():
    wi = random_witness_item()
    bytes_wi = decode_witness_item(wi.bytes)
    hex_wi = decode_witness_item(wi.hex)

    assert bytes_wi.bytes == wi.bytes
    assert hex_wi.bytes == wi.bytes


def test_witness():
    w = random_witness()
    bytes_w = decode_witness(w.bytes)
    hex_w = decode_witness(w.hex)

    assert bytes_w.bytes == w.bytes
    assert hex_w.bytes == w.bytes


def test_transaction():
    # Legacy
    t1 = random_tx(segwit=False)
    bytes_t1 = decode_transaction(t1.bytes)
    hex_t1 = decode_transaction(t1.hex)

    assert bytes_t1.bytes == t1.bytes
    assert hex_t1.bytes == t1.bytes

    # Segwit
    t2 = random_tx(segwit=True)
    bytes_t2 = decode_transaction(t2.bytes)
    hex_t2 = decode_transaction(t2.hex)

    assert bytes_t2.bytes == t2.bytes
    assert hex_t2.bytes == t2.bytes
