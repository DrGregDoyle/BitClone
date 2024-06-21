"""
A file for testing the UTXO class and similar methods
"""
from random import randint

from src.library import decode_outpoint, random_outpoint, decode_utxo, random_utxo


def test_outpoint():
    for x in range(randint(5, 10)):
        temp_outpoint = random_outpoint()
        recovered_outpoint = decode_outpoint(temp_outpoint.encoded)
        assert recovered_outpoint.encoded == temp_outpoint.encoded


def test_utxo():
    random_test_length = randint(5, 10)
    for _ in range(random_test_length):
        temp_utxo = random_utxo()
        recovered_utxo = decode_utxo(temp_utxo.encoded)
        assert temp_utxo.encoded == recovered_utxo.encoded
