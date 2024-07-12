"""
A module for encoding/decoding
"""
from src.block import Header, Block
from src.library.base58 import BASE58_LIST
from src.library.hash_func import sha_256
from src.parse import decode_compact_size, decode_endian
from src.transaction import WitnessItem, Witness, TxInput, TxOutput, Transaction
from src.utxo import Outpoint, UTXO


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
    items, increment = data_list(data[i:], stack_items, "witness_item")
    i += increment

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
    # tx_id | 32 bytes - raw_tx has tx_id in natural byte order
    tx_id = data[:txid_chars]
    index = txid_chars
    # v_out
    v_out = decode_endian(data[index:index + vout_chars])
    index += vout_chars
    # scriptsig
    scriptsig_size, increment = decode_compact_size(data[index:])  # scriptsig_size denotes byte size
    index += increment
    scriptsig = data[index:index + 2 * scriptsig_size]
    index += len(scriptsig)
    # sequence
    sequence = decode_endian(data[index:index + sequence_chars])
    index += sequence_chars

    # verify
    input_data = data[:index]
    temp_input = TxInput(tx_id, v_out, scriptsig, sequence)
    if temp_input.hex != input_data:
        raise ValueError("Constructed TxInput does not agree with original data.")
    return temp_input


def decode_output(data: str | bytes) -> TxOutput:
    # Chars
    amount_chars = TxOutput.AMOUNT_BYTES * 2

    # Get data as hex string
    data = data.hex() if isinstance(data, bytes) else data  # Data is now a hex string

    # Amount | 8 bytes, little-endian
    amount = decode_endian(data[:amount_chars])
    index = amount_chars

    # Script pub key
    scriptpubkey_size, increment = decode_compact_size(data[index:])
    index += increment
    scriptpubkey = data[index:index + 2 * scriptpubkey_size]
    index += len(scriptpubkey)

    # Verify
    original_data = data[:index]
    constructed_output = TxOutput(amount, scriptpubkey)
    if constructed_output.hex != original_data:
        raise ValueError("Constructed TxOutput does not agree with original data.")
    return constructed_output


def decode_transaction(data: str | bytes) -> Transaction:
    # Get data as hex string
    data = data.hex() if isinstance(data, bytes) else data  # Data is now a hex string

    # Fixed chars
    version_chars = Transaction.VERSION_BYTES * 2
    locktime_chars = Transaction.LOCKTIME_BYTES * 2
    sighash_chars = Transaction.SIGHASH_BYTES * 2

    # Version | 4 bytes, little-endian
    version = decode_endian(data[:version_chars])
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
    inputs, increment = data_list(data[index:], input_count, "input")
    index += increment

    # Outputs
    output_count, increment = decode_compact_size(data[index:])
    index += increment
    outputs, increment = data_list(data[index:], output_count, "output")
    index += increment

    # Witness
    witness = []
    if segwit:
        witness, increment = data_list(data[index:], input_count, "witness")
        index += increment

    # Locktime | 4 bytes, little-endian
    locktime = decode_endian(data[index:index + locktime_chars])
    index += locktime_chars

    # Check for sighash
    try:
        sighash = decode_endian(data[index:index + sighash_chars])
    except ValueError:
        sighash = 1

    # Return TX
    if segwit:
        return Transaction(inputs=inputs, outputs=outputs, witness=witness, locktime=locktime,
                           version=version, sighash=sighash)
    else:
        return Transaction(inputs=inputs, outputs=outputs, locktime=locktime, version=version, sighash=sighash)


def decode_base58_check(encoded_data: str, checksum=True):
    total = 0
    data_range = len(encoded_data)
    for x in range(data_range):
        total += BASE58_LIST.index(encoded_data[x:x + 1]) * pow(58, data_range - x - 1)
    if checksum:
        datacheck = format(total, "0x")
        data = datacheck[:-8]
        check = datacheck[-8:]
        assert sha_256(data) == check
    else:
        data = format(total, "0x")
    return data


# --- BLOCK ELEMENTS --- #

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
    version = decode_endian(data[:version_chars])
    index = version_chars

    # prev_block | 32 bytes, natural byte order
    prev_block = data[index:index + prev_block_chars]
    index += prev_block_chars

    # merkle root | 32 bytes, natural byte order
    merkle_root = data[index:index + merkle_root_chars]
    index += merkle_root_chars

    # time | 4 bytes, little-endian
    time = decode_endian(data[index:index + time_chars])
    index += time_chars

    # bits | 4 bytes
    bits = data[index:index + bits_chars]
    index += bits_chars

    # nonce | 4 bytes, little-endian
    nonce = decode_endian(data[index:index + nonce_chars])
    index += nonce_chars

    # Verify
    original = data[:index]
    temp_header = Header(previous_block=prev_block, merkle_root=merkle_root, time=time, bits=bits, nonce=nonce,
                         version=version)
    if temp_header.hex != original:
        raise ValueError("Constructed Header does not agree with original data.")
    return temp_header


def decode_block(data: str | bytes) -> Block:
    data = data.hex() if isinstance(data, bytes) else data  # Data is now a hex string

    # Header
    header = decode_header(data)
    index = len(header.hex)

    # Txs
    tx_count, increment = decode_compact_size(data[index:])
    index += increment
    txs, increment = data_list(data[index:], tx_count, "")
    index += increment

    # Verify
    original_data = data[:index]
    temp_block = Block(header.previous_block.hex, txs, header.time.num, header.bits, header.nonce.num,
                       header.version.num)
    if temp_block.hex != original_data:
        raise ValueError("Constructed Block does not agree with original data.")
    return temp_block


# --- UTXO ELEMENTS --- #
def decode_outpoint(data: str | bytes):
    data = get_hex(data)  # Hex string

    # CHARS
    txid_chars = 2 * Outpoint.TXID_BYTES
    vout_chars = 2 * Outpoint.VOUT_BYTES

    # tx_id is in natural byte order
    txid = data[:txid_chars]
    index = txid_chars

    # v_out
    v_out = decode_endian(data[index:index + vout_chars])
    index += vout_chars

    # Verify
    original_data = data[:index]
    temp_outpoint = Outpoint(txid, v_out)
    if temp_outpoint.hex != original_data:
        raise ValueError("Original data not equal to given Outpoint")
    return temp_outpoint


def decode_utxo(data: str | bytes):
    data = get_hex(data)  # Get data as hex  string

    # Chars
    height_chars = 2 * UTXO.HEIGHT_BYTES
    amount_chars = 2 * UTXO.AMOUNT_BYTES

    # Outpoint
    outpoint = decode_outpoint(data)
    index = len(outpoint.hex)

    # Height, coinbase, amount
    _height = data[index:index + height_chars]
    height = decode_endian(_height)
    index += height_chars
    coinbase = True if data[index:index + 2] == "01" else False
    index += 2
    _amount = data[index:index + amount_chars]
    amount = decode_endian(_amount)
    index += amount_chars

    # Locking code
    locking_code_size, increment = decode_compact_size(data[index:])
    index += increment
    locking_code = data[index:index + 2 * locking_code_size]
    index += 2 * locking_code_size

    # Verify
    original_data = data[:index]
    temp_utxo = UTXO(outpoint, height, amount, locking_code, coinbase)
    if temp_utxo.hex != original_data:
        raise ValueError("Original data not equal to constructed UTXO")
    return temp_utxo


# --- DATA LIST --- #
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
        case "witness_item":
            func = decode_witness_item
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


def get_hex(data: str | bytes):
    # Returns hex string
    return data.hex() if isinstance(data, bytes) else data


# -- TESTING
if __name__ == "__main__":
    tx_data = "0100000001b7994a0db2f373a29227e1d90da883c6ce1cb0dd2d6812e4558041ebbbcfa54b000000006a473044022008f4f37e2d8f74e18c1b8fde2374d5f28402fb8ab7fd1cc5b786aa40851a70cb02201f40afd1627798ee8529095ca4b205498032315240ac322c9d8ff0f205a93a580121024aeaf55040fa16de37303d13ca1dde85f4ca9baa36e2963a27a1c0c1165fe2b1ffffffff01983a0000000000001976a914b3e2819b6262e0b1f19fc7229d75677f347c91ac88ac00000000"
    tx = decode_transaction(tx_data)
    print(tx.to_json())
    print(tx.hex)
    print(tx.hex == tx_data)
    print(f"TXID: {tx.txid}")

    for x in range(0, len(tx_data), 2):
        tx_data_byte = tx_data[x:x + 2]
        tx_hex_byte = tx.hex[x:x + 2]
        if tx_data_byte != tx_hex_byte:
            print(f"BYTE INDEX: {x}")
            print(f"TXDATA: {tx_data_byte}")
            print(f"HEXBYTE: {tx_hex_byte}")
