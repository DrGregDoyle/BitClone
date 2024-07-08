"""
A module for encoding/decoding
"""
from src.block import Header
from src.compact_size import decode_compact_size, ByteOrder
from src.transaction import WitnessItem, Witness, TxInput, TxOutput, Transaction


# --- STRING PARSING --- #


# --- TRANSACTION ELEMENTS --- #

def decode_witness_item(data: str | bytes) -> WitnessItem:
    """
    Decode accepts either hex string or bytes object
    """
    data = data.hex() if isinstance(data, bytes) else data  # Data is now a hex string

    # Get byte size
    wi_byte_size, index = decode_compact_size(data)
    item_chars = 2 * wi_byte_size

    # Item length is 2 * byte size
    item = bytes.fromhex(data[index:index + item_chars])
    index += item_chars

    # Verify
    initial_string = data[:index]
    temp_wi = WitnessItem(item)
    if temp_wi.hex != initial_string:
        raise ValueError("Constructed witness item does not agree with initial string")

    return temp_wi


def decode_witness(data: str | bytes) -> Witness:
    """
    Decode accepts either hex string or bytes object
    """
    data = data.hex() if isinstance(data, bytes) else data  # Data is now a hex string

    # First byte is CompactSize number of items | i = index for string
    stack_items, i = decode_compact_size(data)

    # Get items
    items = []
    for _ in range(stack_items):
        temp_wi = decode_witness_item(data[i:])
        items.append(temp_wi)
        i += len(temp_wi.hex)

    # Verify
    original = data[:i]
    temp_witness = Witness(items)
    if temp_witness.hex != original:
        raise ValueError("Constructed Witness does not agree with original data.")
    return temp_witness


def decode_input(data: str | bytes) -> TxInput:
    """
    Decode accepts either hex string or bytes object
    """
    # Input Chars
    txid_chars = 2 * TxInput.TX_ID_BYTES
    vout_chars = 2 * TxInput.V_OUT_BYTES
    sequence_chars = 2 * TxInput.SEQUENCE_BYTES

    data = data.hex() if isinstance(data, bytes) else data  # Data is now a hex string

    # -- Parse hex string
    index = txid_chars
    # tx_id | 32 bytes
    tx_id = ByteOrder(data[:txid_chars], length=txid_chars // 2)
    # v_out
    v_out = ByteOrder(data[index:index + vout_chars], length=vout_chars // 2)
    index += vout_chars
    # scriptsig
    scripsig_size, increment = decode_compact_size(data[index:])  # scriptsig_size denotes byte size
    index += increment
    scriptsig = ByteOrder(data[index:index + 2 * scripsig_size], length=scripsig_size)
    index += len(scriptsig)
    # sequence
    sequence = ByteOrder(data[index:index + sequence_chars], length=sequence_chars // 2)
    index += sequence_chars

    # verify
    input_data = data[:index]
    temp_input = TxInput(tx_id.little, v_out.little, scriptsig.big, sequence.little)
    if temp_input.hex != input_data:
        print(f"INPUT JSON: {temp_input.to_json()}")
        print(f"TEMP INPUT: {temp_input.hex}")
        print(f"ORIGINAL DATA: {input_data}")
        print(f"DATA STRING: {data}")
        raise ValueError("Constructed TxInput does not agree with original data.")
    return temp_input


def decode_output(data: str | bytes) -> TxOutput:
    # Chars
    amount_chars = TxOutput.AMOUNT_BYTES * 2

    # Get data as hex string
    data = data.hex() if isinstance(data, bytes) else data  # Data is now a hex string

    # Amount | 8 bytes, little-endian
    amount = ByteOrder(data[:amount_chars], length=amount_chars // 2)
    index = amount_chars

    # Script pub key
    scriptpubkey_size, increment = decode_compact_size(data[index:])
    index += increment
    scriptpubkey = ByteOrder(data[index:index + 2 * scriptpubkey_size], length=scriptpubkey_size).big.hex()
    index += len(scriptpubkey)

    # Verify
    original_data = data[:index]
    constructed_output = TxOutput(amount.little_int, scriptpubkey)
    if constructed_output.hex != original_data:
        raise ValueError("Constructed TxOutput does not agree with original data.")
    return constructed_output


def decode_transaction(data: str | bytes) -> Transaction:
    # Get data as hex string
    data = data.hex() if isinstance(data, bytes) else data  # Data is now a hex string

    # Fixed chars
    version_chars = Transaction.VERSION_BYTES * 2
    locktime_chars = Transaction.LOCKTIME_BYTES * 2

    # Version | 4 bytes, little-endian
    # version = int.from_bytes(bytes.fromhex(data[:version_chars]), byteorder="little")  # Version
    version = ByteOrder(data[:version_chars], length=version_chars // 2)
    index = version_chars

    # Check for segwit
    segwit_check = data[index:index + 4]
    segwit = False
    if segwit_check == "0001":
        segwit = True
        index += 4

    # Inputs
    input_count, increment = decode_compact_size(data[index:])
    index += increment
    inputs = []
    for _ in range(input_count):
        temp_input = decode_input(data[index:])
        inputs.append(temp_input)
        index += len(temp_input.hex)

    # Outputs
    output_count, increment = decode_compact_size(data[index:])
    index += increment
    outputs = []
    for _ in range(output_count):
        temp_output = decode_output(data[index:])
        outputs.append(temp_output)
        index += len(temp_output.hex)

    # Witness
    witness = []
    if segwit:
        for _ in range(input_count):
            temp_witness = decode_witness(data[index:])
            witness.append(temp_witness)
            index += len(temp_witness.hex)

    # Locktime | 4 bytes, little-endian
    locktime = ByteOrder(data[index:index + locktime_chars], length=locktime_chars // 2)

    # Return TX
    if segwit:
        return Transaction(inputs=inputs, outputs=outputs, witness=witness, locktime=locktime.little_int,
                           version=version.little_int)
    else:
        return Transaction(inputs=inputs, outputs=outputs, locktime=locktime.little_int, version=version.little_int)


def data_list(data: str, count: int, decode_type: str):
    """
    Given a string of hex data and a count, we return a list of tx elements based on given type.
    """
    # Get decode type
    match decode_type:
        case "input":
            func = decode_input
        case "output":
            func = decode_output
        case "witness":
            func = decode_witness
        case _:
            func = decode_transaction

    # Get list and return
    _data_list = []
    index = 0
    for _ in range(count):
        temp_obj = func(data[index:])
        _data_list.append(temp_obj)
        index += len(temp_obj.hex)
    return _data_list, index


def decode_header(data: str | bytes):
    data = data.hex() if isinstance(data, bytes) else data  # Data is now a hex string

    # header chars
    version_chars = 2 * Header.VERSION_BYTES
    prev_block_chars = 2 * Header.PREVBLOCK_BYTES
    merkle_root_chars = 2 * Header.MERKLE_BYTES
    time_chars = 2 * Header.TIME_BYTES
    bits_chars = 2 * Header.BITS_BYTES
    nonce_chars = 2 * Header.NONCE_BYTES

    # version | 4 bytes, little-endian
    version = ByteOrder(data[:version_chars], length=version_chars // 2).little_int
    index = version_chars

    # prev_block | 32 bytes, natural byte order (little-endian)
    prev_block = ByteOrder(data[index:index + prev_block_chars], length=prev_block_chars // 2).little.hex()
    index += prev_block_chars

    # merkle root | 32 bytes, natural byte order (little-endian)
    merkle_root = ByteOrder(data[index:index + merkle_root_chars], length=merkle_root_chars // 2).little.hex()
    index += merkle_root_chars

    # time | 4 bytes, little-endian
    time = ByteOrder(data[index:index + time_chars], length=time_chars // 2).little_int
    index += time_chars

    # bits | 4 bytes, little-endian
    bits = ByteOrder(data[index:index + bits_chars], length=bits_chars // 2).little.hex()
    index += bits_chars

    # nonce | 4 bytes, little-endian
    nonce = ByteOrder(data[index:index + nonce_chars], length=nonce_chars // 2).little_int
    index += nonce_chars

    # Verify
    original = data[:index]
    temp_header = Header(prev_block=prev_block, merkle_root=merkle_root, time=time, bits=bits, nonce=nonce,
                         version=version)
    if temp_header.hex != original:
        raise ValueError("Constructed Header does not agree with original data.")
    return temp_header


# -- TESTING
if __name__ == "__main__":
    pass
