"""
Transactions
"""
import json


class CompactSize:
    """
    Given a non-negative integer values < 2^64, we return its compactSize encoding. The class maintains both a byte
    and hex encoding.
    """

    def __init__(self, num: int):
        self.bytes = self._get_bytes(num)  # Bytes
        self.hex = self.bytes.hex()  # Hex string
        self.num = num  # Actual integer value

    def _get_bytes(self, num: int):
        if 0 <= num <= 0xfc:
            return num.to_bytes(length=1, byteorder="little")
        elif 0xfd <= num <= 0xffff:
            b1 = 0xfd.to_bytes(length=1, byteorder="big")
            b2 = num.to_bytes(length=2, byteorder="little")
            return b1 + b2
        elif 0x10000 <= num <= 0xffffffff:
            b1 = 0xfe.to_bytes(length=1, byteorder="big")
            b2 = num.to_bytes(length=4, byteorder="little")
            return b1 + b2
        elif 0x100000000 <= num <= 0xffffffffffffffff:
            b1 = 0xff.to_bytes(length=1, byteorder="big")
            b2 = num.to_bytes(length=8, byteorder="little")
            return b1 + b2


def decode_compact_size(data: str | bytes):
    """
    Decode accepts either hex string or bytes object
    """
    data = data.hex() if isinstance(data, bytes) else data  # Data is now a hex string

    first_byte = int.from_bytes(bytes.fromhex(data[:2]), byteorder="big")
    match first_byte:
        case 0xfd:
            num = int.from_bytes(bytes.fromhex(data[2:6]), byteorder="little")
            len = 6
        case 0xfe:
            num = int.from_bytes(bytes.fromhex(data[2:10]), byteorder="little")
            len = 10
        case 0xff:
            num = int.from_bytes(bytes.fromhex(data[2:18]), byteorder="little")
            len = 18
        case _:
            num = int.from_bytes(bytes.fromhex(data[:2]), byteorder="little")
            len = 2
    return num, len


class WitnessItem:
    """
    =========================================
    |   field   |   size    |   format      |
    =========================================
    |   size    |   var     |   CompactSize |
    |   item    |   var     |   bytes       |
    =========================================
    """

    def __init__(self, item: bytes):
        # Item
        self.item = item

        # Size
        item_length = len(self.item)
        self.size = CompactSize(item_length)

    @property
    def bytes(self):
        """
        Returns the byte encoding of the WitnessItem
        """
        return self.size.bytes + self.item

    @property
    def hex(self):
        """
        Returns the hex string corresponding to the byte encoding of the WitnessItem
        """
        return self.bytes.hex()

    def to_json(self):
        witness_item_dict = {
            "size": self.size.hex,
            "item": self.item.hex()
        }
        return json.dumps(witness_item_dict, indent=2)


def decode_witness_item(data: str | bytes) -> WitnessItem:
    """
    Decode accepts either hex string or bytes object
    """
    data = data.hex() if isinstance(data, bytes) else data  # Data is now a hex string

    # Get byte size
    wi_byte_size, index = decode_compact_size(data)

    # Item length is 2 * byte size
    item = bytes.fromhex(data[index:index + 2 * wi_byte_size])
    index += 2 * wi_byte_size

    # Verify
    initial_string = data[:index]
    temp_wi = WitnessItem(item)
    if temp_wi.hex != initial_string:
        raise ValueError("Constructed witness item does not agree with initial string")

    return temp_wi


class Witness:
    """
    =============================================
    |   field       |   size    |   format      |
    =============================================
    |   stack_items |   var     |   CompactSize |
    |   items       |   var     |   WitnessItem |
    =============================================
    The stack_items is the number of WitnessItem items.
    """

    def __init__(self, items: list):
        # WitnessItems
        self.items = items

        # Get stack_items
        item_length = len(self.items)
        self.stack_items = CompactSize(item_length)

    @property
    def bytes(self):
        """
        Get the byte encoding of all elements of the witness.
        """
        witness_bytes = bytes()
        for witness_item in self.items:
            witness_bytes += witness_item.bytes
        return self.stack_items.bytes + witness_bytes

    @property
    def hex(self):
        """
        Get the hex encoding of all elements of the witness.
        """
        return self.bytes.hex()

    def to_json(self):
        witness_dict = {
            "stack_items": self.stack_items.hex
        }
        item_dict = {}
        for item in self.items:
            item_dict.update({
                self.items.index(item): json.loads(item.to_json())
            })
        witness_dict.update({
            "items": item_dict
        })
        return json.dumps(witness_dict, indent=2)


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


class TxInput:
    """
    =========================================================
    |   field           |   size        |   format          |
    =========================================================
    |   tx_id           |   32 bytes    |   little endian   |
    |   v_out           |   4 bytes     |   little endian   |
    |   scriptsig_size  |   var         |   CompactSize     |
    |   scriptsig       |   var         |   Script          |
    |   sequence        |   4 bytes     |   little endian   |
    =========================================================

    """
    TX_ID_BYTES = 32
    V_OUT_BYTES = 4
    SEQUENCE_BYTES = 4

    def __init__(self, tx_id: str | bytes, v_out: int | bytes, scriptsig: str | bytes, sequence: int | None = None):
        """
        The TxInput can be constructed as follows:
            tx_id: hex string given in network byte order
        """
        # tx_id : 32 bytes
        tx_id_num = int(tx_id, 16) if isinstance(tx_id, str) else int(tx_id.hex(), 16)
        self.tx_id = tx_id_num.to_bytes(length=self.TX_ID_BYTES, byteorder="little")

        # v_out : 4 bytes
        v_out_num = v_out if isinstance(v_out, int) else int(v_out.hex(), 16)
        self.v_out = v_out_num.to_bytes(length=self.V_OUT_BYTES, byteorder="little")

        # scriptsig : CompactSize
        self.scriptsig = bytes.fromhex(scriptsig) if isinstance(scriptsig, str) else scriptsig
        script_length = len(self.scriptsig)
        self.scriptsig_size = CompactSize(script_length)

        # sequence : 4 bytes
        seq_num = sequence if isinstance(sequence, int) else 0
        self.sequence = seq_num.to_bytes(length=self.SEQUENCE_BYTES, byteorder="little")

    @property
    def bytes(self):
        return self.tx_id + self.v_out + self.scriptsig_size.bytes + self.scriptsig + self.sequence

    @property
    def hex(self):
        return self.bytes.hex()

    def to_json(self):
        input_dict = {
            "tx_id": self.tx_id.hex(),
            "v_out": self.v_out.hex(),
            "scriptsig_size": self.scriptsig_size.hex,
            "scriptsig": self.scriptsig.hex(),
            "sequence": self.sequence.hex()
        }
        return json.dumps(input_dict, indent=2)


def decode_input(data: str | bytes) -> TxInput:
    """
    Decode accepts either hex string or bytes object
    """
    # Input Chars
    txid_chars = 2 * TxInput.TX_ID_BYTES
    vout_chars = 2 * TxInput.V_OUT_BYTES
    sequence_chars = 2 * TxInput.SEQUENCE_BYTES

    data = data.hex() if isinstance(data, bytes) else data  # Data is now a hex string

    ## Parse hex string
    index = txid_chars
    # tx_id
    tx_id = format(int.from_bytes(bytes.fromhex(data[:index]), byteorder="little"), f"0{txid_chars}x")
    # v_out
    v_out = int.from_bytes(bytes.fromhex(data[index:index + vout_chars]), byteorder="little")
    index += vout_chars
    # scriptsig
    scripsig_size, increment = decode_compact_size(data[index:])  # scriptsig_size denotes byte size
    index += increment
    scriptsig = bytes.fromhex(data[index:index + 2 * scripsig_size]).hex()
    index += len(scriptsig)
    # sequence
    sequence = int.from_bytes(bytes.fromhex(data[index:index + sequence_chars]), byteorder="little")
    index += sequence_chars

    # verify
    input_data = data[:index]
    temp_input = TxInput(tx_id, v_out, scriptsig, sequence)
    if temp_input.hex != input_data:
        raise ValueError("Constructed TxInput does not agree with original data.")
    return temp_input


class TxOutput:
    """
    =============================================================
    |   field               |   byte size   |   format          |
    =============================================================
    |   amount              |   8           |   little-endian   |
    |   script_pub_key_size |   var         |   CompactSize     |
    |   script_pub_key      |   var         |   Script          |
    =============================================================
    """
    AMOUNT_BYTES = 8

    def __init__(self, amount: int | bytes, scriptpubkey: str | bytes):
        # amount : 8 bytes
        amount_int = int.from_bytes(amount) if isinstance(amount, bytes) else amount
        self.amount = amount_int.to_bytes(length=self.AMOUNT_BYTES, byteorder="little")

        # scriptpubkey
        self.scriptpubkey = bytes.fromhex(scriptpubkey) if isinstance(scriptpubkey, str) else scriptpubkey
        script_length = len(self.scriptpubkey)
        self.scriptpubkey_size = CompactSize(script_length)

    @property
    def bytes(self):
        return self.amount + self.scriptpubkey_size.bytes + self.scriptpubkey

    @property
    def hex(self):
        return self.bytes.hex()

    def to_json(self):
        output_dict = {
            "amount": self.amount.hex(),
            "scriptpubkey_size": self.scriptpubkey_size.hex,
            "scriptpubkey": self.scriptpubkey.hex()
        }
        return json.dumps(output_dict, indent=2)


def decode_output(data: str | bytes) -> TxOutput:
    # Chars
    amount_chars = TxOutput.AMOUNT_BYTES * 2

    # Get data as hex string
    data = data.hex() if isinstance(data, bytes) else data  # Data is now a hex string

    # Amount
    amount = int.from_bytes(bytes.fromhex(data[:amount_chars]), byteorder="little")
    index = amount_chars

    # Script pub key
    scriptpubkey_size, increment = decode_compact_size(data[index:])
    index += increment
    scriptpubkey = bytes.fromhex(data[index:index + 2 * scriptpubkey_size]).hex()
    index += len(scriptpubkey)

    # Verify
    original_data = data[:index]
    constructed_output = TxOutput(amount, scriptpubkey)
    if constructed_output.hex != original_data:
        raise ValueError("Constructed TxOutput does not agree with original data.")
    return constructed_output


class Transaction:
    """
    =========================================================
    |   field       |   size            |   format          |
    =========================================================
    |   version     |   4               |   little-endian   |
    |   marker      |   1 (optional)    |   fixed           |
    |   flag        |   1 (optional)    |   fixed           |
    |   num_input   |   var             |   CompactSize     |
    |   inputs      |   var             |   Input.encoded   |
    |   num_output  |   var             |   CompactSize     |
    |   outputs     |   var             |   Output.encoded  |
    |   witness     |   optional        |   Witness.encoded |
    |   locktime    |   4               |   little-endian   |
    =========================================================
    """
    VERSION = 2  # Hardcoded
    VERSION_BYTES = 4
    MARKER = bytes.fromhex("00")
    FLAG = bytes.fromhex("01")
    LOCKTIME_BYTES = 4

    def __init__(self, inputs: list, outputs: list, witness=None, locktime=None, version=VERSION):
        # Version
        self.version = version.to_bytes(length=self.VERSION_BYTES, byteorder="little")

        # Locktime
        locktime = locktime if locktime else 0
        self.locktime = locktime.to_bytes(length=self.LOCKTIME_BYTES, byteorder="little")

        # Inputs
        self.inputs = inputs
        input_num = len(self.inputs)
        self.input_count = CompactSize(input_num)

        # Outputs
        self.outputs = outputs
        output_num = len(self.outputs)
        self.output_count = CompactSize(output_num)

        # Witness/Segwit
        self.segwit = False
        if witness:
            self.segwit = True
        self.witness = witness if self.segwit else None
        self.marker = self.MARKER if self.segwit else None
        self.flag = self.FLAG if self.segwit else None

    @property
    def bytes(self):
        input_bytes = bytes()
        for i in self.inputs:
            input_bytes += i.bytes
        output_bytes = bytes()
        for o in self.outputs:
            output_bytes += o.bytes
        if self.segwit:
            witness_bytes = bytes()
            for w in self.witness:
                witness_bytes += w.bytes
            return (self.version + self.marker + self.flag + self.input_count.bytes + input_bytes
                    + self.output_count.bytes + output_bytes + witness_bytes + self.locktime)
        return (self.version + self.input_count.bytes + input_bytes + self.output_count.bytes + output_bytes
                + self.locktime)

    @property
    def hex(self):
        return self.bytes.hex()

    def to_json(self):
        # Version
        tx_dict = {
            "version": self.version.hex()
        }

        # Marker/Flag
        if self.segwit:
            tx_dict.update({
                "marker": self.marker.hex(),
                "flag": self.flag.hex()
            })

        # Inputs
        input_list = []
        for x in range(self.input_count.num):
            temp_input = self.inputs[x]
            input_list.append(json.loads(temp_input.to_json()))
        tx_dict.update({
            "input_count": self.input_count.hex,
            "inputs": input_list
        })

        # Outputs
        output_list = []
        for y in range(self.output_count.num):
            temp_output = self.outputs[y]
            output_list.append(json.loads(temp_output.to_json()))
        tx_dict.update({
            "output_count": self.output_count.hex,
            "outputs": output_list
        })

        # Witness
        if self.segwit:
            witness_list = []
            for z in range(self.input_count.num):
                temp_witness = self.witness[z]
                witness_list.append(json.loads(temp_witness.to_json()))
            tx_dict.update({
                "witness": witness_list
            })

        # Locktime
        tx_dict.update({
            "locktime": self.locktime.hex()
        })
        return json.dumps(tx_dict, indent=2)


def decode_transaction(data: str | bytes) -> Transaction:
    # Get data as hex string
    data = data.hex() if isinstance(data, bytes) else data  # Data is now a hex string

    # Fixed chars
    version_chars = Transaction.VERSION_BYTES * 2
    locktime_chars = Transaction.LOCKTIME_BYTES * 2

    # Version
    version = int.from_bytes(bytes.fromhex(data[:version_chars]), byteorder="little")  # Version
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
            index += temp_witness.hex

    # Locktime
    locktime = int.from_bytes(bytes.fromhex(data[index:index + locktime_chars]), byteorder="little")

    # Return TX
    if segwit:
        return Transaction(inputs=inputs, outputs=outputs, witness=witness, locktime=locktime)
    else:
        return Transaction(inputs=inputs, outputs=outputs, locktime=locktime)


# --- TESTING
from hashlib import sha256
from random import choice, randint
from string import ascii_letters


def random_string(string_length=64):
    _string = ""
    for _ in range(string_length):
        _string += choice(ascii_letters)
    return _string


def random_item(byte_size=64):
    data = random_string(byte_size)
    return sha256(data.encode()).digest()


def random_witness_item():
    item = random_item()
    return WitnessItem(item)


def random_witness():
    stack_items = randint(1, 10)
    items = [random_witness_item() for _ in range(stack_items)]
    return Witness(items)


def random_vout():
    return randint(0, pow(2, 16) - 1)


def random_amount():
    return randint(1, pow(2, 64) - 1)


def random_input():
    tx_id = random_item()
    vout = random_vout()
    sequence = random_vout()
    scriptsig = random_item(byte_size=128).hex()
    return TxInput(tx_id, vout, scriptsig, sequence)


def random_output():
    amount = random_amount()
    scriptpubkey = random_item(byte_size=128).hex()
    return TxOutput(amount, scriptpubkey)


if __name__ == "__main__":
    input1 = random_input()
    input2 = random_input()
    output1 = random_output()

    tx1 = Transaction(inputs=[input1, input2], outputs=[output1])
    print(tx1.to_json())
    construct = decode_transaction(tx1.hex)
    print(construct.to_json())
    print(f"NO WITNESS CONSTRUCT AGREE: {tx1.hex == construct.hex}")
