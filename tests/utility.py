"""
Helper functions for tests
"""

# --- IMPORTS --- #
from random import randint, choice
from secrets import randbits
from string import ascii_letters

# from src.decoder_lib import BYTE_DICT
from src.transaction import TxInput, TxOutput, WitnessItem, Witness, Transaction


# --- RANDOM TYPES --- #

def random_string(string_length=64):
    _string = ""
    for _ in range(string_length):
        _string += choice(ascii_letters)
    return _string


def random_bytes(byte_length=64):
    bits = byte_length * 8
    random_num = randbits(bits)
    return random_num.to_bytes(length=byte_length, byteorder="big")


# --- TRANSACTION --- #

def random_witness_item(byte_length=64):
    item = random_bytes(byte_length)
    return WitnessItem(item)


def random_witness(item_num=None, byte_length=64):
    stack_items = item_num if item_num else randint(1, 10)
    items = [random_witness_item(byte_length) for _ in range(stack_items)]
    return Witness(items)


def random_input():
    tx_id = random_bytes(byte_length=TxInput.TX_ID_BYTES)
    vout = int.from_bytes(random_bytes(byte_length=TxInput.V_OUT_BYTES), byteorder="big")
    sequence = int.from_bytes(random_bytes(byte_length=TxInput.SEQUENCE_BYTES), byteorder="big")
    scriptsig = random_bytes().hex()
    return TxInput(tx_id, vout, scriptsig, sequence)


def random_output():
    amount = int.from_bytes(random_bytes(byte_length=TxOutput.AMOUNT_BYTES), byteorder="big")
    scriptpubkey = random_bytes().hex()
    return TxOutput(amount, scriptpubkey)


def random_tx(byte_length=64, segwit=None):
    # Version/Locktime
    version = int.from_bytes(random_bytes(byte_length=Transaction.VERSION_BYTES), byteorder="big")
    locktime = int.from_bytes(random_bytes(byte_length=Transaction.LOCKTIME_BYTES), byteorder="big")

    # Inputs
    input_num = randint(1, 5)
    inputs = [random_input() for _ in range(input_num)]

    # Outputs
    output_num = randint(1, 5)
    outputs = [random_output() for _ in range(output_num)]

    # Witness
    segwit = choice([True, False]) if segwit is None else segwit
    if segwit:
        witness = [random_witness(byte_length=byte_length) for _ in range(input_num)]
        return Transaction(inputs=inputs, outputs=outputs, witness=witness, locktime=locktime, version=version)
    return Transaction(inputs=inputs, outputs=outputs, locktime=locktime, version=version)

# ---- DEADLINE ---- #


# def random_outpoint():
#     tx_id = random_tx_id()
#     v_out = random_byte_element("v_out")
#     return Outpoint(tx_id, v_out)
#
#
# def random_utxo():
#     outpoint = random_outpoint()
#     height = random_byte_element("height")
#     amount = random_byte_element("amount")
#     locking_code = random_tx_id()
#     coinbase = random_bool()
#     return UTXO(outpoint, height, amount, locking_code, coinbase)
#
#
# def random_block():
#     prev_block = random_tx_id()
#     # bits = random_byte_element("bits")
#     bits = get_random_bits()
#     time = random_byte_element("time")
#     nonce = random_byte_element("nonce")
#     version = random_byte_element("version")
#     tx_count = 2  # randint(3, 5)
#     segwit = random_bool()
#     tx_list = [random_tx(segwit) for _ in range(tx_count)]
#     return Block(
#         prev_block=prev_block,
#         tx_list=tx_list,
#         nonce=nonce,
#         time=time,
#         bits=bits,
#         version=version
#     )
