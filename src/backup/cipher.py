"""
Methods for encoding and decoding
"""
import re

from src.backup.library.ecc import SECP256K1
from src.tx import Outpoint, UTXO, WitnessItem, Witness, TxInput, TxOutput, Transaction

from src.backup.library import OPCODES
from src.backup.library.base58 import BASE58_LIST
from src.backup.library.hash_func import hash256
from src.library.primitive import Endian


def decompress_public_key(cpk: str):
    curve = SECP256K1()
    parity = 0 if cpk[:2] == "02" else 1
    x = int(cpk[2:], 16)
    y1 = curve.get_y_from_x(x)
    y2 = curve.p - y1
    y = y1 if y1 % 2 == parity else y2
    return x, y


def decode_compact_size(data: str | bytes):
    """
    Decode accepts either hex string or bytes object
    """
    # Get hex
    data = get_hex(data)

    first_byte = int.from_bytes(bytes.fromhex(data[:2]), byteorder="big")
    match first_byte:
        case 0xfd | 0xfe | 0xff:
            l_index = 2
            diff = first_byte - 0xfb
            r_index = 2 + pow(2, diff)
        case _:
            l_index = 0
            r_index = 2
    num = int.from_bytes(bytes.fromhex(data[l_index: r_index]), byteorder="little")
    return num, r_index


def decode_endian(data: str | bytes) -> int:
    # Get hex string
    data = get_hex(data)

    # reverse data order
    _atad = "".join([data[x:x + 2] for x in reversed(range(0, len(data), 2))])

    # return integer
    return int(_atad, 16)


def decode_outpoint(data: str | bytes) -> Outpoint:
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


def decode_utxo(data: str | bytes) -> UTXO:
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


def decode_witness_item(data: str | bytes) -> WitnessItem:
    """
    Decode accepts either hex string or bytes object
    """
    data = get_hex(data)

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
    # Hex string
    data = data.hex() if isinstance(data, bytes) else data  # Data is now a hex string

    # First byte is CompactSize number of items | i = index for string
    stack_items, i = decode_compact_size(data)

    # Get items
    items, increment = _data_list(data[i:], stack_items, "witness_item")
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
    txid_chars = 2 * Outpoint.TXID_BYTES
    vout_chars = 2 * Outpoint.VOUT_BYTES
    sequence_chars = 2 * TxInput.SEQUENCE_BYTES

    # Hex string
    data = get_hex(data)

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
    temp_input = TxInput(Outpoint(tx_id, v_out), scriptsig, sequence)
    if temp_input.hex != input_data:
        raise ValueError("Constructed TxInput does not agree with original data.")
    return temp_input


def decode_output(data: str | bytes) -> TxOutput:
    # Chars
    amount_chars = TxOutput.AMOUNT_BYTES * 2

    # Get data as hex string
    data = get_hex(data)

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
    inputs, increment = _data_list(data[index:], input_count, "input")
    index += increment

    # Outputs
    output_count, increment = decode_compact_size(data[index:])
    index += increment
    outputs, increment = _data_list(data[index:], output_count, "output")
    index += increment

    # Witness
    witness = []
    if segwit:
        witness, increment = _data_list(data[index:], input_count, "witness")
        index += increment

    # Locktime | 4 bytes, little-endian
    locktime = decode_endian(data[index:index + locktime_chars])
    index += locktime_chars

    # Return TX
    if segwit:
        return Transaction(inputs=inputs, outputs=outputs, witness=witness, locktime=locktime, version=version)
    else:
        return Transaction(inputs=inputs, outputs=outputs, locktime=locktime, version=version)


def decode_script(scriptpubkey: str | bytes) -> list:
    """
    We decode the scriptPubKey hex string to a list of ASM values
    """
    _script = get_hex(scriptpubkey)

    def find_opcode(value_int: int):
        result = [k for k, v in OPCODES.items() if v == value_int]
        if result:
            return result[0]
        return None

    _asm = []
    index = 0
    # Gather OP CODES
    while index < len(_script):
        temp_byte = _script[index:index + 2]
        temp_int = int(temp_byte, 16)
        index += 2
        if 1 <= temp_int <= 75:  # PUSH DATA
            _op_code = f"OP_PUSHBYTES_{str(temp_int)}"
            hex_data_length = 2 * temp_int
            _asm.extend([_op_code, _script[index:index + hex_data_length]])
            index += hex_data_length
        else:
            _asm.append(find_opcode(temp_int))

    return _asm


def encode_script(asm: list):
    """
    Given a list of op-codes and data we return the corresponding hex value.
    """
    _script = ""
    for s in asm:
        if s[:3] == "OP_":
            if s[3:12] == "PUSHBYTES":
                _script += format(int(s[-2:]), "02x")
            else:
                _script += format(OPCODES.get(s), "02x")
        else:
            _script += s
    return _script


def encode_signature(sig: tuple, sighash=None) -> bytes:
    """
    via Pieter Wuille:
        A correct DER-encoded signature has the following form:

        0x30: a header byte indicating a compound structure.
        A 1-byte length descriptor for all what follows.
        0x02: a header byte indicating an integer.
        A 1-byte length descriptor for the R value
        The R coordinate, as a big-endian integer.
        0x02: a header byte indicating an integer.
        A 1-byte length descriptor for the S value.
        The S coordinate, as a big-endian integer.
    """
    # Headers
    cs_header = bytes.fromhex("30")
    int_header = bytes.fromhex("02")

    # Get integer values of signature
    r, s = sig

    # Format r
    hex_r = r.to_bytes(length=32, byteorder="big").hex()
    binary_r = format(r, "0256b")  # 256 bits
    if binary_r[0] == "1":
        # Signed int - prepend byte
        hex_r = "00" + hex_r
    byte_r = bytes.fromhex(hex_r)
    byte_encoded_r = int_header + len(byte_r).to_bytes(length=1, byteorder="big") + byte_r

    # Format s
    hex_s = s.to_bytes(length=32, byteorder="big").hex()
    binary_s = format(s, "0256b")
    if binary_s[0] == "1":
        hex_s = "00" + hex_s
    byte_s = bytes.fromhex(hex_s)
    byte_encoded_s = int_header + len(byte_s).to_bytes(length=1, byteorder="big") + byte_s

    # Format DER
    der_length = len(byte_encoded_r + byte_encoded_s)  # Byte length

    # Add sighash
    _sighash = 1 if sighash is None else sighash
    sighash_bytes = Endian(_sighash, length=1).bytes

    # Return bytes
    return cs_header + der_length.to_bytes(length=1, byteorder="big") + byte_encoded_r + byte_encoded_s + sighash_bytes


def decode_signature(der_encoded: str | bytes):
    # get data as hex string
    der_encoded = der_encoded.hex() if isinstance(der_encoded, bytes) else der_encoded

    # Config
    i = 0
    byte_chars = 2

    # Get DER values
    header = der_encoded[:i]
    i += byte_chars
    sig_length = int(der_encoded[i:i + byte_chars], 16)
    i += byte_chars

    # Get R values
    r_int_type = der_encoded[i:i + 2]
    i += byte_chars
    r_length = int(der_encoded[i:i + 2], 16)
    i += byte_chars
    r = int(der_encoded[i: i + 2 * r_length], 16)
    i += 2 * r_length

    # Get S values
    s_int_type = der_encoded[i:i + 2]
    i += byte_chars
    s_length = int(der_encoded[i:i + 2], 16)
    i += byte_chars
    s = int(der_encoded[i: i + 2 * s_length], 16)
    i += 2 * s_length

    # Get hashtype byte
    hash_type = der_encoded[i:]
    # TODO: Implement hash type

    return (r, s)


def encode_base58check(payload: str, version_byte=0):
    # Handle version
    version = "3" if version_byte == 5 else "1"
    prefix = "05" if version_byte == 5 else "00"

    # Get checksum
    checksum = bytes.fromhex(hash256(prefix + payload))[:4]  # Checksum is first 4 bytes
    print(f"CHECKSUM: {checksum.hex()}")

    # Convert address
    hex_address = payload + checksum.hex()
    address = ""
    num = int(hex_address, 16)
    while num > 0:
        r = num % 58
        address = BASE58_LIST[r] + address
        num = num // 58

    address = version + address
    return address


def decode_base58check(payload: str):
    total = 0

    # Decode string
    r_payload = "".join([payload[x:x + 1] for x in reversed(range(0, len(payload)))])
    for n in range(len(r_payload)):
        c = r_payload[n]
        c_i = BASE58_LIST.index(c)
        val = pow(58, n) * c_i
        total += val

    # Break up hex into version_byte + payload and checksum
    hex_val = format(total, "0x")
    checksum = hex_val[-8:]
    l1_num = re.match(r"^([1]+)", payload).group()
    leading_zeros = "00" * int(l1_num)
    hex_addr = leading_zeros + hex_val[:-8]

    # Verify checksum
    check = hash256(hex_addr)[:8]
    if check != checksum:
        print(f"INITIAL PAYLOAD: {payload}")
        print(f"HEX ADDRESS: {hex_addr}")
        print(f"CHECK: {check}, CHECKSUM: {checksum}")  # TESTING
        raise ValueError("Checksum of recovered data not equal to given checksum.")

    return hex_addr[2:]  # Remove version byte from address


def encode_bech32(payload: str, hrp="bc", witness_version=0):
    bech32_alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    # Convert payload to binary string
    binary_payload = format(int(payload, 16), f"0{len(payload) * 4}b")
    print(f"BINARY PAYLOAD: {binary_payload}")
    print(f"BINARY PAYLOAD LENGTH: {len(binary_payload)}")
    # Squash data
    squash_list = [format(int(binary_payload[x:x + 5], 2), "02x") for x in range(0, len(binary_payload), 5)]
    print(squash_list)
    print([int(s, 16) for s in squash_list])
    data_hex = "".join(squash_list)

    # Add witness version byte to data_hex
    data_hex = format(witness_version, "02x") + data_hex
    print(f"DATA WITH WITNESS VERSION: {data_hex}")

    # Compute checksum by using data_hex and HRP
    checksum = polymod_checksum(data_hex, hrp)


def polymod_checksum(payload: str, hrp="bc"):
    # Start with checksum = 1
    checksum = 1

    # Process HRP
    for ch in hrp:
        print(ch)


# --- DATA LIST --- #
def _data_list(data: str, count: int, decode_type: str):
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


# --- GET FORMAT --- #
def get_hex(data: str | bytes):
    # Returns hex string
    return data.hex() if isinstance(data, bytes) else data


def get_bytes(data: str | bytes):
    # Returns byte string
    return bytes.fromhex(data) if isinstance(data, str) else data


# -- TESTING
if __name__ == "__main__":
    _hex_string = "751e76e8199196d454941c45d1b3a323f1433bd6"
    encode_bech32(_hex_string)
