"""
Helper functions for tests
"""
from hashlib import sha256
# --- IMPORTS --- #
from random import randint, choice
from string import ascii_letters

from src.block import Block
from src.decoder_lib import BYTE_DICT
from src.transaction import Input, Output, WitnessItem, Witness, Transaction
from src.utxo import Outpoint, UTXO


# --- RANDOM --- #

def get_random_string(max_chars=64):
    random_string = ""
    for _ in range(max_chars):
        random_string += choice(ascii_letters)
    return random_string


def random_tx_id():
    random_string = get_random_string()
    return sha256(random_string.encode()).hexdigest()


def random_bool():
    return choice([True, False])


def random_integer_range(lower=1, upper=10):
    return randint(lower, upper)


def get_random_integer(int_bytes=4):
    upper = pow(2, int_bytes)
    return randint(1, upper)


def random_byte_element(element: str):
    return get_random_integer(BYTE_DICT.get(element))


def random_outpoint():
    tx_id = random_tx_id()
    v_out = random_byte_element("v_out")
    return Outpoint(tx_id, v_out)


def random_utxo():
    outpoint = random_outpoint()
    height = random_byte_element("height")
    amount = random_byte_element("amount")
    locking_code = random_tx_id()
    coinbase = random_bool()
    return UTXO(outpoint, height, amount, locking_code, coinbase)


def random_input(segwit=None):
    segwit = random_bool() if segwit is None else segwit
    tx_id = random_tx_id()
    v_out = random_byte_element("v_out")
    script_sig = random_tx_id() if not segwit else ""
    sequence = random_byte_element("sequence")
    witness = random_witness() if segwit else None
    return Input(tx_id, v_out, script_sig, sequence, witness)


def random_output():
    amount = random_byte_element("amount")
    output_script = random_tx_id()
    return Output(amount, output_script)


def random_witness_item():
    item = random_tx_id() + random_tx_id()
    return WitnessItem(item)


def random_witness():
    random_num_of_wi = randint(2, 4)
    items = []
    for _ in range(random_num_of_wi):
        items.append(random_witness_item())
    return Witness(items)


def random_tx(segwit=None):
    input_count = 1  # randint(2, 5)
    inputs = []
    segwit = random_bool() if segwit is None else segwit
    for _ in range(input_count):
        inputs.append(random_input(segwit))

    output_count = 1  # randint(1, 3)
    outputs = []
    for _ in range(output_count):
        outputs.append(random_output())

    version = random_byte_element("version")
    locktime = random_byte_element("locktime")
    return Transaction(inputs, outputs, version=version, locktime=locktime)


def random_block():
    prev_block = random_tx_id()
    target = random_byte_element("target")
    time = random_byte_element("time")
    nonce = random_byte_element("nonce")
    version = random_byte_element("version")
    tx_count = 2  # randint(3, 5)
    segwit = random_bool()
    tx_list = [random_tx(segwit) for _ in range(tx_count)]
    return Block(
        prev_block=prev_block,
        tx_list=tx_list,
        nonce=nonce,
        time=time,
        target=target,
        version=version
    )
