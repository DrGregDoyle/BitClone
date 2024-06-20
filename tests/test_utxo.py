"""
A file for testing the UTXO class and similar methods
"""
from src.utility import random_tx_id, random_v_out, random_height, random_amount, random_hash256, random_bool
from src.utxo import Outpoint, decode_outpoint, UTXO, decode_utxo


def test_outpoint():
    tx_id = random_tx_id()
    v_out = random_v_out()

    random_outpoint = Outpoint(tx_id=tx_id, v_out=v_out)
    constructed_outpoint = decode_outpoint(random_outpoint.encoded)
    assert random_outpoint.encoded == constructed_outpoint.encoded


def test_utxo():
    tx_id = random_tx_id()
    v_out = random_v_out()
    height = random_height()
    amount = random_amount()
    locking_code = random_hash256(128)
    coinbase = random_bool()

    random_outpoint = Outpoint(tx_id=tx_id, v_out=v_out)
    random_utxo = UTXO(outpoint=random_outpoint, height=height, amount=amount, locking_code=locking_code,
                       coinbase=coinbase)
    constructed_utxo = decode_utxo(random_utxo.encoded)
    assert constructed_utxo.encoded == random_utxo.encoded
