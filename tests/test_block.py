"""
Testing Block and related classes
"""
from random import randint

from src.block import Header, decode_header, Block, decode_block
from src.transaction import Input, Output, Witness, WitnessItem, Transaction
from src.utility import *
from src.wallet import WalletFactory


def random_header() -> Header:
    prev_block = random_tx_id()
    merkle_root = random_hash256()
    target = random_integer(4)
    test_time = random_integer(4)
    nonce = random_integer(4)
    return Header(prev_block=prev_block, merkle_root=merkle_root, target=target, nonce=nonce,
                  timestamp=test_time)


def random_tx() -> Transaction:
    random_wallet = WalletFactory().new_wallet()

    # Inputs
    random_num_inputs = randint(1, 3)
    input_list = []
    for _ in range(random_num_inputs):
        tx_id = random_tx_id()
        v_out = random_v_out()
        script_sig = random_wallet.sign_transaction(tx_id=tx_id)
        temp_input = Input(tx_id, v_out, script_sig)
        input_list.append(temp_input)

    # Outputs
    random_num_outputs = randint(1, 3)
    output_list = []
    for _ in range(random_num_outputs):
        amount = random_amount()
        output_script = hash160(random_tx_id())
        temp_output = Output(amount, output_script)
        output_list.append(temp_output)

    # Witness
    witness_list = []
    for _ in range(random_num_inputs):
        item_list = []
        random_num_items = randint(1, 3)
        for _ in range(random_num_items):
            item = random_tx_id()
            witness_item = WitnessItem(item)
            item_list.append(witness_item)
        temp_witness = Witness(item_list)
        witness_list.append(temp_witness)

    # Return Transaction
    return Transaction(inputs=input_list, outputs=output_list, witness_list=witness_list)


def test_header():
    header1 = random_header()
    constructed_header = decode_header(header1.encoded)
    assert constructed_header.encoded == header1.encoded


def test_block():
    # Header
    header1 = random_header()

    # Txs
    tx_num = randint(1, 5)
    tx_list = [random_tx() for _ in range(tx_num)]

    # Block
    block1 = Block(header=header1, tx_list=tx_list)
    constructed_block = decode_block(block1.encoded)
    assert constructed_block.encoded == block1.encoded
