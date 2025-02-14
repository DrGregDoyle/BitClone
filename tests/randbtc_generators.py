"""
Methods for generating random BitClone objects
"""
from secrets import token_bytes, randbits, randbelow

from src.tx import Input, Output, WitnessItem, Witness, Transaction


def get_random_input(scriptsig_bits: int = 16):
    rand_scriptsig_size = randbits(scriptsig_bits)
    return Input(
        txid=token_bytes(32),  # txid | 32 bytes
        vout=randbits(32),  # vout | 4 bytes
        script_sig=token_bytes(rand_scriptsig_size),  # scriptsig | var len
        sequence=randbits(32)  # sequqnce | 4 bytes
    )


def get_random_output(scriptpubkey_bits: int = 8):
    rand_scriptpubkey_sze = randbits(scriptpubkey_bits)
    return Output(
        amount=randbits(64),  # 8 byte integer
        script_pubkey=token_bytes(rand_scriptpubkey_sze)  # script pubkey | var len
    )


def get_random_witness_item(item_bits: int = 8):
    rand_witnessitem_size = randbits(item_bits)
    return WitnessItem(
        item=token_bytes(rand_witnessitem_size)
    )


def get_random_witness(wit_num: int = 3):
    rand_witnum = randbelow(wit_num) + 1
    return Witness(
        items=[get_random_witness_item() for _ in range(rand_witnum)]
    )


def get_random_tx(input_num: int = 3, output_num: int = 3, is_segwit: bool = True):
    rand_input_num = randbelow(input_num) + 1
    rand_output_num = randbelow(output_num) + 1
    rand_inputs = [get_random_input() for _ in range(rand_input_num)]
    rand_outputs = [get_random_output() for _ in range(rand_output_num)]

    rand_witness = [get_random_witness() for _ in range(rand_input_num)] if is_segwit else []
    rand_locktime = randbits(32)  # 4 byte integer
    rand_version = randbits(32)  # 4 bytes integer

    return Transaction(
        inputs=rand_inputs,
        outputs=rand_outputs,
        witnesses=rand_witness,
        locktime=rand_locktime,
        version=rand_version
    )
