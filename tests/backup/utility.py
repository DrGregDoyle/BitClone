"""
Utility functions for tests
"""
from random import choice
from secrets import randbits

from src.cipher import encode_base58check
from src.backup.library.hash_func import hash256
from src.tx import Outpoint, UTXO, WitnessItem, Witness, TxInput, TxOutput


def random_bool():
    return choice([True, False])


def random_hex(bit_size=256):
    hex_alphabet = "0123456789abcdef"
    return "".join([choice(hex_alphabet) for _ in range((bit_size + 3) // 4)])


def random_hash(bit_size=256):
    return hash256(random_hex(bit_size))


def random_int(bit_size=256):
    return randbits(bit_size)


def random_outpoint():
    tx_id = random_hash()
    v_out = random_int(4)
    return Outpoint(tx_id, v_out)


def random_utxo():
    _outpt = random_outpoint()

    height = random_int(20)
    amount = random_int(24)
    scriptpubkey = random_hex(128)
    coinbase = random_bool()

    return UTXO(_outpt, height, amount, scriptpubkey, coinbase)


def random_witness_item(bit_size=256):
    return WitnessItem(random_hex(bit_size))


def random_witness():
    item_num = random_int(4)
    item_list = [random_witness_item() for _ in range(item_num)]
    return Witness(item_list)


def random_txinput():
    outpoint = random_outpoint()
    scriptsig = random_hex()
    sequence = random_int(32)
    return TxInput(outpoint, scriptsig, sequence)


def random_txoutput():
    amount = random_int(64)
    scriptpubkey = random_hex()
    return TxOutput(amount, scriptpubkey)


def random_base58check(bit_size=256):
    data = random_hex(bit_size)
    return encode_base58check(data)
