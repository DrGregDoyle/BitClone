"""
Methods for encoding and decoding
"""
from src.library.ecc import SECP256K1
from src.library.op_codes import OPCODES
from src.tx import Outpoint, UTXO, WitnessItem, Witness, TxInput, TxOutput, Transaction


def decode_compressed_public_key(cpk: str):
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


def decode_scriptpubkey(scriptpubkey: str | bytes) -> list:
    """
    We decode the scriptPubKey hex string to a list of ASM values
    """
    _script = scriptpubkey.hex() if isinstance(scriptpubkey, bytes) else scriptpubkey

    def find_opcode(value_int: int):
        result = [k for k, v in OPCODES.items() if v == value_int]
        if result:
            return result[0]
        return None

    _asm = []
    index = 0
    # Gather OP CODES
    while index < len(scriptpubkey):
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


# --- TESTING

if __name__ == "__main__":
    txdata = "010000000532748a0af868b473b81cbdf4cc8f7e9cb29636f8782d82c927effcee5468745b2d0300006a473044022042f368d76f5d938c9e4a36e9b029f5b0e115f7acc23c0f31540b6d9ab84b5fa402200f263a17161b53928a88ba2a7992416673edbcbdbf0c8f9a94eb9c26a21acfec012102dcd8b4cf56a5e928647bec8cc9bd62d7650360644674f0751f1cedf8c4f5ebc2ffffffff4c0345dd9643a19ebc76426901fdadd5488b226751b5341776d1d20d3f890b1f2a0300006b483045022100fe21eeac788e52a61f94414e200789ab37622487ffc745304491736f72329e1e02207b972928c38e9450029a60de2e6c9e900d1ed9d3cfe5f75a81bbee59835648d7012102dcd8b4cf56a5e928647bec8cc9bd62d7650360644674f0751f1cedf8c4f5ebc2ffffffffa05ff1514c6267f06443c11a3720a987a76292545faf326090524cb66a3b28e2250300006a4730440220075c0b745acf349820e545df782d6fde36350d219e669a588165b40b494c792b02201096faa13539d1855cd9b578f623f516b6a8b880ec5c803d6f444097ddcbcae6012102dcd8b4cf56a5e928647bec8cc9bd62d7650360644674f0751f1cedf8c4f5ebc2ffffffff7036640251866bf65cad59f6bfbe9d80a9c76238f3042dfbef0cd079b06b6e372a0300006a47304402200278632c774b4f4e5c66922d1b6a6a70664c584ff50892ba89791c5d864c751d02202620cb1d26aefe3f6210023bbf692025955f1670ac08b2b4652d300ea1dbd07e012102dcd8b4cf56a5e928647bec8cc9bd62d7650360644674f0751f1cedf8c4f5ebc2ffffffff9429229bde034b119d28ed0d92f65e5f1c3ec9e4ef11ec9323ba7f48bc2e2b912a0300006a47304402207e80c8c7a094f7117cccb54b1d1ce7330098995eb6d30a279b66117d7a36be5002206b12110baab13a6e58e5a0d8256b309760f552139b13b6636facc3e4bea21eeb012102dcd8b4cf56a5e928647bec8cc9bd62d7650360644674f0751f1cedf8c4f5ebc2ffffffff01e0c86307000000001976a91418395131f8853df5fafc2d4b6374d1c065e2d8a688ac00000000"
    tx = decode_transaction(txdata)
    print(tx.to_json())
