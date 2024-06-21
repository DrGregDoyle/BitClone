"""
A file for testing Transaction and its related classes. Both decoding and encoding
"""
# --- IMPORTS --- #
from random import randint

from src.library import decode_input, decode_output, decode_witness_item, decode_witness, decode_tx
from src.transaction import Input, Output, WitnessItem, Witness, Transaction
from src.utility import random_hash160, hash256
from src.wallet import WalletFactory


# --- TESTS --- #


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


def test_witness_item():
    random_tx_id = hash256(random_hash160())
    test_wi = WitnessItem(item=random_tx_id)
    constructed_wi = decode_witness_item(test_wi.encoded)
    assert constructed_wi.encoded == test_wi.encoded


def test_witness():
    wi1 = WitnessItem(item=hash256(random_hash160()))
    wi2 = WitnessItem(item=hash256(random_hash160()))
    test_w = Witness(items=[wi1, wi2])
    constructed_witness = decode_witness(test_w.encoded)
    assert constructed_witness.encoded == test_w.encoded


def test_transaction():
    tx_id1 = hash256(random_hash160())
    tx_id2 = hash256(random_hash160())
    tx_id3 = hash256(random_hash160())
    rand_int1 = randint(1, 100)
    rand_int2 = randint(1, 100)
    rand_int3 = randint(1, 100)

    test_wallet = WalletFactory().new_wallet()
    sig1 = test_wallet.sign_transaction(tx_id=tx_id1)
    sig2 = test_wallet.sign_transaction(tx_id=tx_id2)

    input1 = Input(tx_id=tx_id1, v_out=rand_int1, script_sig=sig1)
    input2 = Input(tx_id=tx_id2, v_out=rand_int2, script_sig=sig2)

    output1 = Output(amount=rand_int3, output_script=tx_id3)

    item1 = WitnessItem(tx_id1)
    item2 = WitnessItem(tx_id2)
    witness1 = Witness(items=[item1])
    witness2 = Witness(items=[item2])
    witness_list = [witness1, witness2]

    test_tx = Transaction(inputs=[input1, input2], outputs=[output1], witness_list=witness_list)
    constructed_tx = decode_tx(test_tx.encoded)

    assert constructed_tx.encoded == test_tx.encoded
