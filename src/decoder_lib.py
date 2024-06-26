"""
A library for common decoder functions
"""

# --- IMPORTS --- #

from src.block import Block
from src.encoder_lib import BYTE_DICT
from src.transaction import Input, Output, WitnessItem, Witness, Transaction
from src.utxo import Outpoint, UTXO


# --- PARSERS --- #
def parse_string(s: str, index: int, length: int):
    string_length = index + length
    return s[index: string_length], string_length


def parse_num(s: str, index: int, length: int, internal=False):
    """
    Set internal=True to parse a number given in internal byte order (little-endian).
    Default is for internal=False and the chars are in display byte order (big-endian).
    """
    string_length = index + length
    temp_string = s[index:string_length]
    num = temp_string[::-1] if internal else temp_string
    return int(num, 16), string_length


# --- DECODE --- #


def decode_compact_size(s: str) -> int | tuple:
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
    return int(n, 16), len(n)


def decode_outpoint(s: str) -> Outpoint:
    # Hex characters
    tx_chars = 2 * BYTE_DICT.get("tx")
    v_out_chars = 2 * BYTE_DICT.get("v_out")

    # tx_id
    tx_id, i = parse_string(s, index=0, length=tx_chars)

    # v_out - little-endian
    v_out, i = parse_num(s, index=i, length=v_out_chars, internal=True)

    # verify and return
    string_encoding = s[:tx_chars + v_out_chars]
    outpoint = Outpoint(tx_id, v_out)
    if outpoint.encoded != string_encoding:
        raise TypeError("Input string did not generate same Outpoint object")
    return outpoint


def decode_utxo(s: str) -> UTXO:
    # Chars
    height_chars = 2 * BYTE_DICT.get("height")
    amount_chars = 2 * BYTE_DICT.get("amount")

    # Outpoint
    outpoint = decode_outpoint(s)
    i = len(outpoint.encoded)  # Running index

    # Height
    height, i = parse_num(s, i, height_chars)

    # Coinbase
    val, i = parse_string(s, i, 2)
    coinbase = True if int(val, 16) > 0 else False

    # Amount - little endian
    amount, i = parse_num(s, i, amount_chars, internal=True)

    # Locking Code
    size, increment = decode_compact_size(s[i:])
    locking_code, i = parse_string(s, i + increment, size)

    # Verify
    string_encoding = s[:i]
    constructed_utxo = UTXO(outpoint, height, amount, locking_code, coinbase)
    if constructed_utxo.encoded != string_encoding:
        raise TypeError("Input string did not generate same UTXO object")
    return constructed_utxo


def decode_input(s: str) -> Input:
    # Chars
    tx_chars = 2 * BYTE_DICT.get("tx")
    v_out_chars = 2 * BYTE_DICT.get("v_out")
    sequence_chars = 2 * BYTE_DICT.get("sequence")

    # tx_id
    tx_id, i = parse_string(s, 0, tx_chars)

    # v_out - little endian
    v_out, i = parse_num(s, i, v_out_chars, internal=True)

    # script_sig
    script_sig_size, increment = decode_compact_size(s[i:])
    script_sig, i = parse_string(s, i + increment, script_sig_size)

    # sequence - little endian
    sequence, i = parse_num(s, i, sequence_chars, internal=True)

    # Verify
    string_encoding = s[:i]
    constructed_input = Input(tx_id, v_out, script_sig, sequence)
    if constructed_input.encoded != string_encoding:
        raise TypeError("Input string did not generate same Input object")
    return constructed_input


def decode_output(s: str) -> Output:
    # Chars
    amount_chars = 2 * BYTE_DICT.get("amount")

    # Amount - little endian
    amount, i = parse_num(s, 0, amount_chars, internal=True)

    # Output script
    script_size, increment = decode_compact_size(s[i:])
    output_script, i = parse_string(s, i + increment, script_size)

    # Verify
    string_encoding = s[:i]
    constructed_output = Output(amount, output_script)
    if constructed_output.encoded != string_encoding:
        raise TypeError("Input string did not generate same Output object")
    return constructed_output


def decode_witness_item(s: str) -> WitnessItem:
    # Item
    item_size, i = decode_compact_size(s)
    item = s[i:i + item_size]

    # Verify
    string_encoding = s[:i + item_size]
    constructed_witness_item = WitnessItem(item)
    if constructed_witness_item.encoded != string_encoding:
        raise TypeError("Input string did not generate same WitnessItem object")
    return constructed_witness_item


def decode_witness(s: str) -> Witness:
    # Stack items
    stack_items, i = decode_compact_size(s)

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
    version_chars = 2 * BYTE_DICT.get("version")
    locktime_chars = 2 * BYTE_DICT.get("locktime")

    # Version - little endian
    version, i = parse_num(s, 0, version_chars, internal=True)

    # Handle Marker/Flag
    segwit = (s[i:i + 4] == "0001")
    if segwit:
        i += 4

    # Get inputs
    input_list = []
    num_inputs, increment = decode_compact_size(s[i:])
    i += increment
    for _ in range(num_inputs):
        temp_input = decode_input(s[i:])
        input_list.append(temp_input)
        i += len(temp_input.encoded)

    # Get outputs
    output_list = []
    num_outputs, increment = decode_compact_size(s[i:])
    i += increment
    for _ in range(num_outputs):
        temp_output = decode_output(s[i:])
        output_list.append(temp_output)
        i += len(temp_output.encoded)

    # Handle Witness
    if segwit:
        # Number of Witnesses must agree with number of inputs
        for n in range(num_inputs):
            temp_witness = decode_witness(s[i:])
            temp_input = input_list[n]
            temp_input.add_witness(temp_witness)
            i += len(temp_witness.encoded)

    # Locktime
    locktime = int(s[i:i + locktime_chars][::-1], 16)  # Little Endian
    i += locktime_chars

    # Verify
    string_encoding = s[:i]
    constructed_tx = Transaction(input_list, output_list, version=version, locktime=locktime)
    if constructed_tx.encoded != string_encoding:
        raise TypeError("Input string did not generate same Transaction object")
    return constructed_tx


def decode_block(s: str) -> Block:
    # -- Header

    # Chars
    version_chars = 2 * BYTE_DICT.get("version")
    prev_block_chars = 2 * BYTE_DICT.get("hash")
    merkle_root_chars = 2 * BYTE_DICT.get("hash")
    time_chars = 2 * BYTE_DICT.get("time")
    bits_chars = 2 * BYTE_DICT.get("bits")
    nonce_chars = 2 * BYTE_DICT.get("nonce")

    # Version - little endian
    version, i = parse_num(s, 0, version_chars, internal=True)

    # Previous block, merkle_root
    prev_block, i = parse_string(s, i, prev_block_chars)
    merkle_root, i = parse_string(s, i, merkle_root_chars)

    # Time - little endian
    time, i = parse_num(s, i, time_chars, internal=True)

    # Bits - unique little-endian formatting
    bits, i = parse_string(s, i, bits_chars)
    coeff = bits[:6][::-1]  # Little-endian coeff
    exp = bits[6:]  # Big-endian exp
    bits = exp + coeff

    # Nonce - little endian
    nonce, i = parse_num(s, i, nonce_chars, internal=True)

    # Txs
    tx_count, increment = decode_compact_size(s[i:])
    i += increment
    tx_list = []
    for x in range(tx_count):
        temp_tx = decode_tx(s[i:])
        tx_list.append(temp_tx)
        i += len(temp_tx.encoded)

    # Verify
    string_encoding = s[:i]
    constructed_block = Block(prev_block, tx_list, nonce, time, bits, version)
    if constructed_block.encoded != string_encoding:
        raise TypeError("Input string did not generate same Block object")
    return constructed_block
