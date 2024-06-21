"""
Various common methods
# TODO: Move random to tests.utility
"""

from random import randint

from src.transaction import Input, Output, WitnessItem, Witness, Transaction
from src.utility import random_tx_id, random_v_out, random_height, random_amount, random_hash256, hash160, random_bool, \
    random_integer, hash256, random_hash160
# --- IMPORTS --- #
from src.utxo import Outpoint, UTXO

# --- METHODS --- #
BYTE_DICT = {
    "tx": 32,
    "v_out": 4,
    "height": 16,
    "amount": 8,
    "sequence": 4,
    "byte": 1,
    "version": 4,
    "locktime": 4
}


def get_chars(byte_dict_key):
    return 2 * BYTE_DICT.get(byte_dict_key)


# --- ENCODE --- #

def encode_compact_size(n: int) -> str:
    """
    We return a variable length integer in hex such that the first byte indicates the length
    """
    if 0 <= n <= 0xFC:
        return format(n, f"02x")
    elif 0xFD <= n <= 0xFFFF:
        return "fd" + format(n, f"04x")
    elif 0X10000 <= n <= 0xFFFFFFFF:
        return "fe" + format(n, f"08x")
    elif 0x100000000 <= n <= 0xffffffffffffffff:
        return "ff" + format(n, f"016x")


# --- DECODE --- #

def decode_compact_size(s: str, return_length=False) -> int | tuple:
    chunk = s[:2]
    chunk_int = int(chunk, 16)
    match chunk_int:
        case 253:
            n = s[2:6]
        case 254:
            n = s[2:10]
        case 255:
            n = s[2:18]
        case _:
            n = chunk
    length = len(n)
    if return_length:
        return int(n, 16), length
    else:
        return int(n, 16)


def decode_outpoint(s: str) -> Outpoint:
    # Hex characters
    tx_chars = get_chars("tx")
    v_out_chars = get_chars("v_out")

    # tx_id
    tx_id = s[:tx_chars]

    # v_out - Little Endian
    v_out = int(s[tx_chars:tx_chars + v_out_chars][::-1], 16)

    # verify and return
    string_encoding = s[:tx_chars + v_out_chars]
    outpoint = Outpoint(tx_id, v_out)
    if outpoint.encoded != string_encoding:
        raise TypeError("Input string did not generate same Outpoint object")
    return outpoint


def decode_utxo(s: str) -> UTXO:
    # Chars
    height_chars = get_chars("height")
    amount_chars = get_chars("amount")

    # Outpoint
    outpoint = decode_outpoint(s)
    i = len(outpoint.encoded)  # Running index

    # Height
    height = int(s[i: i + height_chars], 16)
    i += height_chars

    # Coinbase
    val = int(s[i:i + 2], 16)
    coinbase = True if val > 0 else False
    i += 2

    # Amount
    amount = int(s[i: i + amount_chars][::-1], 16)  # Little Endian
    i += amount_chars

    # Locking Code
    size, increment = decode_compact_size(s[i:], return_length=True)
    i += increment
    locking_code = s[i: i + size]

    # Verify
    string_encoding = s[:i + size]
    constructed_utxo = UTXO(outpoint, height, amount, locking_code, coinbase)
    if constructed_utxo.encoded != string_encoding:
        raise TypeError("Input string did not generate same UTXO object")
    return constructed_utxo


def decode_input(s: str) -> Input:
    # Chars
    tx_chars = get_chars("tx")
    v_out_chars = get_chars("v_out")
    sequence_chars = get_chars("sequence")

    # tx_id
    tx_id = s[:tx_chars]
    i = tx_chars  # Running index

    # v_out
    v_out = int(s[i: i + v_out_chars][::-1], 16)  # Little Endian
    i += v_out_chars

    # script_sig
    script_sig_size, increment = decode_compact_size(s[i:], return_length=True)
    i += increment
    script_sig = s[i: i + script_sig_size]
    i += script_sig_size

    # sequence
    sequence = int(s[i: i + sequence_chars][::-1], 16)  # Little Endian
    i += sequence_chars

    # Verify
    string_encoding = s[:i]
    constructed_input = Input(tx_id, v_out, script_sig, sequence)
    if constructed_input.encoded != string_encoding:
        raise TypeError("Input string did not generate same Input object")
    return constructed_input


def decode_output(s: str) -> Output:
    # Chars
    amount_chars = get_chars("amount")

    # Amount
    amount = int(s[:amount_chars][::-1], 16)  # Little Endian
    i = amount_chars  # Index

    # Output script
    script_size, increment = decode_compact_size(s[i:], return_length=True)
    i += increment
    output_script = s[i:i + script_size]

    # Verify
    string_encoding = s[:i + script_size]
    constructed_output = Output(amount, output_script)
    if constructed_output.encoded != string_encoding:
        raise TypeError("Input string did not generate same Output object")
    return constructed_output


def decode_witness_item(s: str) -> WitnessItem:
    # Item
    item_size, i = decode_compact_size(s, return_length=True)
    item = s[i:i + item_size]

    # Verify
    string_encoding = s[:i + item_size]
    constructed_witness_item = WitnessItem(item)
    if constructed_witness_item.encoded != string_encoding:
        raise TypeError("Input string did not generate same WitnessItem object")
    return constructed_witness_item


def decode_witness(s: str) -> Witness:
    # Stack items
    stack_items, i = decode_compact_size(s, return_length=True)

    # Iterate over stack items to get witness items
    items = []
    for _ in range(stack_items):
        temp_wi = decode_witness_item(s[i:])
        items.append(temp_wi)
        i += len(temp_wi.encoded)

    # Verify
    string_encoding = s[:i]
    constructed_witness = Witness(items)
    if constructed_witness.encoded != string_encoding:
        raise TypeError("Input string did not generate same Witness object")
    return constructed_witness


def decode_tx(s: str) -> Transaction:
    # Chars
    version_chars = get_chars("version")
    locktime_chars = get_chars("locktime")

    # Version
    version = int(s[:version_chars][::-1], 16)  # Little Endian
    i = version_chars  # Running index

    # Handle MarkerFlag
    markerflag = s[i:i + 4]
    segwit = (markerflag == "0001")
    if segwit: i += 4

    # Get inputs
    input_list = []
    num_inputs, increment = decode_compact_size(s[i:], return_length=True)
    i += increment
    for _ in range(num_inputs):
        temp_input = decode_input(s[i:])
        input_list.append(temp_input)
        i += len(temp_input.encoded)

    # Get outputs
    output_list = []
    num_outputs, increment = decode_compact_size(s[i:], return_length=True)
    i += increment
    for _ in range(num_outputs):
        temp_output = decode_output(s[i:])
        output_list.append(temp_output)
        i += len(temp_output.encoded)

    # Handle Witness
    witnesses = []
    if segwit:
        # Number of Witnesses must agree with number of inputs
        for _ in range(num_inputs):
            temp_witness = decode_witness(s[i:])
            witnesses.append(temp_witness)
            i += len(temp_witness.encoded)

    # Locktime
    locktime = int(s[i:i + locktime_chars][::-1], 16)  # Little Endian
    i += locktime_chars

    # Verify
    string_encoding = s[:i]
    constructed_tx = Transaction(input_list, output_list, witness_list=witnesses, version=version, locktime=locktime)
    if constructed_tx.encoded != string_encoding:
        raise TypeError("Input string did not generate same Transaction object")
    return constructed_tx


# --- RANDOM --- #


def random_outpoint():
    tx_id = random_tx_id()
    v_out = random_v_out()
    return Outpoint(tx_id, v_out)


def random_utxo():
    outpoint = random_outpoint()
    height = random_height()
    amount = random_amount()
    locking_code = hash160(random_hash256())
    coinbase = random_bool()
    return UTXO(outpoint, height, amount, locking_code, coinbase)


def random_input():
    tx_id = random_tx_id()
    v_out = random_v_out()
    script_sig = hash160(random_hash256()) + hash160(random_hash256())
    sequence = random_integer(4)
    return Input(tx_id, v_out, script_sig, sequence)


def random_output():
    amount = random_amount()
    output_script = hash160(random_hash256()) + hash256(random_hash160())
    return Output(amount, output_script)


def random_witness_item():
    item = random_hash256() + random_hash160()
    return WitnessItem(item)


def random_witness():
    random_num_of_wi = randint(2, 4)
    items = []
    for _ in range(random_num_of_wi):
        items.append(random_witness_item())
    return Witness(items)


def random_tx():
    input_count = randint(2, 5)
    inputs = []
    for _ in range(input_count):
        inputs.append(random_input())

    output_count = randint(1, 3)
    outputs = []
    for _ in range(output_count):
        outputs.append(random_output())

    witness_list = []
    segwit = random_bool()
    if segwit:
        for _ in range(input_count):
            witness_list.append(random_witness())

    version = random_integer(BYTE_DICT.get("version"))
    locktime = random_integer(BYTE_DICT.get("locktime"))
    return Transaction(inputs, outputs, witness_list=witness_list, version=version, locktime=locktime)


# --- TESTING --- #
if __name__ == "__main__":
    tx1 = random_tx()

    print(f"TX1: {tx1.to_json()}")
    tx2 = decode_tx(tx1.encoded)
    print(f"TX2: {tx2.to_json()}")
    print(f"TX1 ENCODED: {tx1.encoded}")
    print(f"TX2 ENCODED: {tx2.encoded}")
