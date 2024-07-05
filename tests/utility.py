"""
Test utilities
"""

from random import choice
from secrets import randbits

from src.block import Header
from src.merkle import create_merkle_tree
from src.transaction import WitnessItem, Witness, TxInput, TxOutput, Transaction


# --- RANDOM --- #
def random_bytes(byte_length=4):
    bit_length = byte_length * 8
    random_integer = randbits(bit_length)
    return random_integer.to_bytes(length=byte_length, byteorder="big")


def random_witness_item(byte_length=32):
    item = random_bytes(byte_length=byte_length)
    return WitnessItem(item)


def random_witness(item_num=1, byte_length=32):
    items = [random_witness_item(byte_length) for _ in range(item_num)]
    return Witness(items)


def random_txinput():
    tx_id = random_bytes(byte_length=TxInput.TX_ID_BYTES)
    v_out = random_bytes(byte_length=TxInput.V_OUT_BYTES)
    scriptsig = random_bytes(byte_length=20)
    sequence = random_bytes(byte_length=TxInput.SEQUENCE_BYTES)
    return TxInput(tx_id, v_out, scriptsig, sequence)


def random_txoutput():
    amount = random_bytes(byte_length=TxOutput.AMOUNT_BYTES)
    scriptpubkey = random_bytes(byte_length=20)
    return TxOutput(amount, scriptpubkey)


def random_tx(input_num=1, output_num=1, segwit=None):
    version = random_bytes(byte_length=Transaction.VERSION_BYTES)
    locktime = random_bytes(byte_length=Transaction.LOCKTIME_BYTES)
    inputs = [random_txinput() for _ in range(input_num)]
    outputs = [random_txoutput() for _ in range(output_num)]
    segwit = choice([True, False]) if segwit is None else segwit
    witness = [random_witness() for _ in range(input_num)] if segwit else None
    return Transaction(inputs, outputs, witness, locktime, version)


def random_txid(input_num=1, output_num=1, segwit=None):
    tx = random_tx(input_num, output_num, segwit)
    return tx.txid


def random_header(tx_num=1):
    tx_list = [random_tx().txid for _ in range(tx_num)]
    merkle_tree = create_merkle_tree(tx_list)
    merkle_root = merkle_tree.get(0)

    prev_block = random_bytes(byte_length=32).hex()

    time = int(random_bytes().hex(), 16)
    bits = random_bytes().hex()
    nonce = int(random_bytes().hex(), 16)
    version = int(random_bytes().hex(), 16)

    return Header(prev_block, merkle_root, time, bits, nonce, version)


if __name__ == "__main__":
    val1 = random_bytes()
    print(val1.hex())
