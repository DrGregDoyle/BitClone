"""
A library for common decoder functions
"""

# --- IMPORTS --- #
from hashlib import sha256
from random import randint, choice
from string import ascii_letters

from src.block import Header, Block
from src.transaction import Input, Output, WitnessItem, Witness, Transaction
from src.utxo import Outpoint, UTXO

# --- FORMATTING --- #
BYTE_DICT = {
    "tx": 32,
    "v_out": 4,
    "height": 16,
    "amount": 8,
    "sequence": 4,
    "byte": 1,
    "version": 4,
    "locktime": 4,
    "hash": 32,
    "target": 4,
    "time": 4,
    "nonce": 4
}


def get_chars(byte_dict_key):
    return 2 * BYTE_DICT.get(byte_dict_key)


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


def decode_header(s: str) -> Header:
    # Chars
    version_chars = get_chars("version")
    prev_block_chars = get_chars("hash")
    merkle_root_chars = get_chars("hash")
    time_chars = get_chars("time")
    target_chars = get_chars("target")
    nonce_chars = get_chars("nonce")

    # Running index
    i = 0

    # Version
    version = int(s[i:i + version_chars][::-1], 16)  # Little Endian
    i += version_chars

    # Previous block
    prev_block = s[i:i + prev_block_chars]
    i += prev_block_chars

    # Merkle root
    merkle_root = s[i: i + merkle_root_chars]
    i += merkle_root_chars

    # Time
    time = int(s[i: i + time_chars][::-1], 16)  # Little Endian
    i += time_chars

    # Target
    target = int(s[i:i + target_chars][::-1], 16)  # Little Endian
    i += target_chars

    # Nonce
    nonce = int(s[i: i + nonce_chars][::-1], 16)  # Nonce
    i += nonce_chars

    # Verify
    string_encoding = s[:i]
    constructed_header = Header(prev_block, merkle_root, time, target, nonce, version=version)
    if constructed_header.encoded != string_encoding:
        raise TypeError("Input string did not generate same Header object")
    return constructed_header


def decode_block(s: str) -> Block:
    # Header
    header = decode_header(s)
    i = len(header.encoded)  # Running index

    # Txs
    tx_count, increment = decode_compact_size(s[i:], return_length=True)
    i += increment
    tx_list = []
    for _ in range(tx_count):
        temp_tx = decode_tx(s[i:])
        tx_list.append(temp_tx)
        i += len(temp_tx.encoded)

    # Verify
    string_encoding = s[:i]
    constructed_block = Block(header, tx_list)
    if constructed_block.encoded != string_encoding:
        raise TypeError("Input string did not generate same Block object")
    return constructed_block


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


def get_random_integer(bytes=4):
    upper = pow(2, bytes)
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


def random_input():
    tx_id = random_tx_id()
    v_out = random_byte_element("v_out")
    script_sig = random_tx_id()
    sequence = random_byte_element("sequence")
    return Input(tx_id, v_out, script_sig, sequence)


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


def random_header() -> Header:
    prev_block = random_tx_id()
    merkle_root = random_tx_id()
    target = random_byte_element("target")
    time = random_byte_element("time")
    nonce = random_byte_element("nonce")
    version = random_byte_element("version")
    return Header(prev_block, merkle_root, time, target, nonce, version)


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

    version = random_byte_element("version")
    locktime = random_byte_element("locktime")
    return Transaction(inputs, outputs, witness_list=witness_list, version=version, locktime=locktime)


def random_block():
    header = random_header()
    tx_count = randint(3, 5)
    tx_list = [random_tx() for _ in range(tx_count)]
    return Block(header, tx_list)


# --- TESTING --- #
if __name__ == "__main__":
    b1 = random_block()
    print(b1.header.to_json())
    b2 = decode_block(b1.encoded)
    print(f"HEADER 2: {b2.header.to_json()}")
