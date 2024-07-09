"""
Test utilities
"""

from random import choice, randint
from secrets import randbits

from src.block import Header, Block
from src.merkle import create_merkle_tree
from src.transaction import WitnessItem, Witness, TxInput, TxOutput, Transaction
from src.utxo import Outpoint, UTXO


# --- RANDOM --- #
def random_int(byte_size=4):
    return randbits(byte_size * 8)


def random_bytes(byte_size=4):
    return random_int(byte_size).to_bytes(length=byte_size, byteorder="big")


def random_witness_item(byte_size=32):
    item = random_bytes(byte_size=byte_size)
    return WitnessItem(item)


def random_witness(item_num=1, byte_size=32):
    items = [random_witness_item(byte_size) for _ in range(item_num)]
    return Witness(items)


def random_txinput():
    tx_id = random_bytes(byte_size=TxInput.TX_ID_BYTES)
    v_out = random_int(byte_size=TxInput.V_OUT_BYTES)
    scriptsig = random_bytes(byte_size=20)
    sequence = random_int(byte_size=TxInput.SEQUENCE_BYTES)
    return TxInput(tx_id, v_out, scriptsig, sequence)


def random_txoutput():
    amount = random_int(byte_size=TxOutput.AMOUNT_BYTES)
    scriptpubkey = random_bytes(byte_size=20)
    return TxOutput(amount, scriptpubkey)


def random_tx(input_num=1, output_num=1, segwit=None):
    version = random_int(byte_size=Transaction.VERSION_BYTES)
    locktime = random_int(byte_size=Transaction.LOCKTIME_BYTES)
    inputs = [random_txinput() for _ in range(input_num)]
    outputs = [random_txoutput() for _ in range(output_num)]
    segwit = choice([True, False]) if segwit is None else segwit
    witness = [random_witness() for _ in range(input_num)] if segwit else None
    return Transaction(inputs, outputs, witness, locktime, version)


def random_txid(input_num=1, output_num=1, segwit=None):
    tx = random_tx(input_num, output_num, segwit)
    return tx.txid


def random_bits():
    exp = randint(20, 30)
    precision = int(random_bytes(byte_size=3).hex(), 16)
    return format(exp, "02x") + format(precision, "06x")


def random_header(tx_num=1, tx_list=None):
    tx_list = [random_txid() for _ in range(tx_num)] if tx_list is None else tx_list
    merkle_tree = create_merkle_tree(tx_list)
    merkle_root = merkle_tree.get(0)

    prev_block = random_bytes(byte_size=32).hex()

    time = random_int(byte_size=Header.TIME_BYTES)
    bits = random_bits()
    nonce = random_int(byte_size=Header.NONCE_BYTES)
    version = random_int(byte_size=Header.VERSION_BYTES)

    return Header(prev_block, merkle_root, time, bits, nonce, version)


def random_block(tx_num=3, segwit=None, nonce=None):
    segwit = choice([True, False]) if segwit is None else segwit
    tx_list = [random_tx(segwit=segwit) for _ in range(tx_num)]

    prev_block = random_bytes(byte_size=32).hex()

    time = random_int(byte_size=Header.TIME_BYTES)
    bits = random_bits()
    nonce = random_int(byte_size=Header.NONCE_BYTES) if nonce is None else nonce
    version = random_int(byte_size=Header.VERSION_BYTES)
    return Block(prev_block, tx_list, time, bits, nonce, version)


def random_outpoint():
    tx = random_tx()
    tx_id = tx.reverse_byte_order
    v_out = randint(0, tx.output_count.num)
    return Outpoint(tx_id, v_out)


def random_utxo():
    outpoint = random_outpoint()
    height = random_int(byte_size=UTXO.HEIGHT_BYTES)
    amount = random_int(byte_size=UTXO.AMOUNT_BYTES)
    locking_code = random_bytes(byte_size=20).hex()
    coinbase = choice([True, False])
    return UTXO(outpoint, height, amount, locking_code, coinbase)


if __name__ == "__main__":
    val1 = random_bytes()
    print(val1.hex())
