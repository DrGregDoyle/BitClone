"""
A page for the Transaction class

Notes:
    -If using segwit, the marker must be zero (0x00) and the flag must be nonzero (0x01).
    -If not using segwit, the marker and flag must not be included in the transaction
    -The unit of measurement for Bitcoin is called "weight". We say that 4 weight = 1 vbyte.
    -To calculate the weight of a field in a transaction, multiply the byte size of the field by the associated factor
        =====               =====
        Field               Factor
        -----               -----
        Version             4
        Marker/Flag         1
        Inputs Count        4
        Outpoint            4
        Input Script        4
        Sequence            4
        Outputs Count       4
        Amount              4
        Output Script       4
        Witness Count       1
        Witness Items       1
        Lock Time           4
        -----               -----

 === Structure of a transaction ===
    Version: 4 bytes
    Marker: segwit optional 1 byte
    Flag: segwit optional 1 byte
    Inputs:
        --
        count: compactSize unsigned integer (variable integer)
        outpoint:
            --
            txid: 32 byte
            output_index: 4 byte (index starting at 0)
        input script:
        sequence:
    Outputs:
        --
        count: compactSize integer (greater than 0)
        amount/value: 8-byte *signed* integer (min = 0, max = 21 000 000 000 000 000)
        script_length: compactSize integer
    Witness:
        --
        count: compactSize integer
    Lock Time:

"""

# --- IMPORTS --- #
import json
import logging
import sys

from src.utility import *

# --- LOGGING --- #
log_level = logging.DEBUG
logger = logging.getLogger(__name__)
logger.setLevel(log_level)
logger.addHandler(logging.StreamHandler(stream=sys.stdout))


# --- CLASSES --- #


class CompactSize:

    def __init__(self, n: int):
        """
        Given a non-negative integer n we return a variable length encoding of maximum 9 byte length
        """
        self.int_value = n
        self.encoded = self.get_encoding()

    def get_encoding(self):
        """
        We return the encoding of n assuming 0 <= n < 2^32
        """
        # Get hex value and prepend string
        hex_val = hex(self.int_value)
        raw_hex = hex_val[2:]
        prepend = ""

        # Modify raw_hex and prepend based on size
        if 0 <= self.int_value <= 0xFC:
            raw_hex = raw_hex.zfill(2)  # Make a 1 byte string = 2 hex chars
        elif 0xFD <= self.int_value <= 0xFFFF:
            raw_hex = raw_hex.zfill(4)
            prepend += "FD"
        elif 0X10000 <= self.int_value <= 0xFFFFFFFF:
            raw_hex = raw_hex.zfill(8)
            prepend += "FE"
        elif 0x100000000 <= self.int_value <= 0xffffffffffffffff:
            raw_hex = raw_hex.zfill(16)
            prepend += "FF"

        # Return prepend string + hex string of number
        return prepend + raw_hex


def match_byte_chunk(byte_chunk: str) -> int:
    """
    Given a byte chunk, we return the necessary index to increment by to capture the number in a string
    """
    match byte_chunk.upper():
        case "FD":
            return 4
        case "FE":
            return 8
        case "FF":
            return 16
    return 0


class Input:
    """
    Input Fields
    =========================================================
    |   field           |   byte size   |   format          |
    =========================================================
    |   tx_id           |   32          |   big-endian      |
    |   v_out           |   4           |   little-endian   |
    |   script_sig_size |   var         |   CompactSize     |
    |   script_sig      |   var         |   Script          |
    |   sequence        |   4           |   little-endian   |
    =========================================================
    """
    TX_BYTES = 32
    INDEX_BYTES = 4
    SEQUENCE_BYTES = 4

    def __init__(self, tx_id: str, v_out: int, script_sig: str, sequence=None):
        # Format tx_id
        self.tx_id = tx_id.zfill(2 * self.TX_BYTES)

        # Little endian format for v_out and sequence
        self.v_out = format(v_out, f"0{2 * self.INDEX_BYTES}x")[::-1]
        temp_sequence = sequence if sequence else pow(2, 8 * self.SEQUENCE_BYTES) - 1
        self.sequence = format(temp_sequence, f"0{2 * self.SEQUENCE_BYTES}x")[::-1]

        # Get script and script_size
        self.script_sig = script_sig
        self.script_sig_size = CompactSize(len(self.script_sig)).encoded

    def __eq__(self, other):
        return self.encoded == other.encoded

    @property
    def encoded(self):
        return self.tx_id + self.v_out + self.script_sig_size + self.script_sig + self.sequence

    @property
    def index_int(self):
        return int(self.v_out[::-1], 16)

    def outpoint(self):
        outpoint_dict = {
            "tx_id": self.tx_id,
            "v_out": self.v_out
        }
        return json.dumps(outpoint_dict, indent=2)

    def to_json(self):
        input_dict = {
            "tx_id": self.tx_id,
            "v_out": self.v_out,
            "script_sig_size": self.script_sig_size,
            "script_sig": self.script_sig,
            "sequence": self.sequence
        }
        return json.dumps(input_dict, indent=2)


def decode_input(input_string: str) -> Input:
    # Get hex character values for formatting
    tx_chars = 2 * Input.TX_BYTES
    vout_chars = 2 * Input.INDEX_BYTES
    seq_chars = 2 * Input.SEQUENCE_BYTES

    # Get tx_id and v_out
    tx_id = input_string[:tx_chars]
    v_out = input_string[tx_chars:tx_chars + vout_chars]  # Little Endian
    v_out_int = int(v_out[::-1], 16)

    # Update current index
    current_index = tx_chars + vout_chars

    # Match byte chunk
    byte_chunk = input_string[current_index:current_index + 2]
    current_index += 2
    increment = match_byte_chunk(byte_chunk)

    # Get script sig size
    script_sig_size = input_string[current_index:current_index + increment] if increment else byte_chunk
    current_index += increment

    # Get script
    script_sig_size_int = int(script_sig_size, 16)
    script_sig = input_string[current_index:current_index + script_sig_size_int]
    current_index += script_sig_size_int

    # Get sequence
    sequence = input_string[current_index:current_index + seq_chars]  # Little Endian
    sequence_int = int(sequence[::-1], 16)

    # Construct input and verify
    constructed_encoding = tx_id + v_out + script_sig_size + script_sig + sequence
    constructed_input = Input(tx_id=tx_id, v_out=v_out_int, script_sig=script_sig, sequence=sequence_int)
    if constructed_input.encoded != constructed_encoding:
        raise TypeError("Given input string did not generate same Input object")
    return constructed_input


class Output:
    """
    Output Fields
    =============================================================
    |   field               |   byte size   |   format          |
    =============================================================
    |   amount              |   8           |   little-endian   |
    |   script_pub_key_size |   var         |   CompactSize     |
    |   script_pub_key      |   var         |   Script          |
    =============================================================
    """
    AMOUNT_BYTES = 8

    def __init__(self, amount: int, output_script: str):
        # Get amount and format it
        self.amount = format(amount, f"0{2 * self.AMOUNT_BYTES}x")[::-1]  # Little Endian

        # Get script and script size
        self.script_pub_key = output_script
        self.script_pub_key_size = CompactSize(len(self.script_pub_key)).encoded

    @property
    def encoded(self):
        return self.amount + self.script_pub_key_size + self.script_pub_key

    @property
    def amount_int(self):
        return int(self.amount[::-1], 16)

    def to_json(self):
        output_dict = {
            "amount": self.amount,
            "script_pub_key_size": self.script_pub_key_size,
            "script_pub_key": self.script_pub_key
        }
        return json.dumps(output_dict, indent=2)


def decode_output(output_string: str) -> Output:
    # Get character counts from Output class
    amount_chars = 2 * Output.AMOUNT_BYTES

    # Set index
    current_index = 0

    # Get amount
    amount = output_string[:amount_chars]  # Little Endian
    amount_int = int(amount[::-1], 16)
    current_index += amount_chars

    # Decode script length
    byte_chunk = output_string[current_index: current_index + 2]
    current_index += 2
    increment = match_byte_chunk(byte_chunk)
    script_pub_key_size = output_string[current_index:current_index + increment] if increment else byte_chunk
    current_index += increment
    script_pub_key_size_int = int(script_pub_key_size, 16)

    # Get script
    script_pub_key = output_string[current_index:current_index + script_pub_key_size_int]

    # Construct Output and verify
    constructed_encoding = amount + script_pub_key_size + script_pub_key
    constructed_output = Output(amount_int, script_pub_key)
    if constructed_output.encoded != constructed_encoding:
        raise TypeError("Given input string did not generate same Output object")
    return constructed_output


class WitnessItem:
    """
    Item Fields
    =========================================
    |   field   |   size    |   format
    =========================================
    |   size    |   var     |   CompactSize |
    |   item    |   var     |   Bytes       |
    =========================================
    """

    def __init__(self, item: str):
        self.size = CompactSize(len(item)).encoded
        self.item = item

    @property
    def encoded(self):
        return self.size + self.item

    def to_json(self):
        wi_dict = {
            "size": self.size,
            "item": self.item
        }
        return json.dumps(wi_dict, indent=2)


def decode_witness_item(wi_string: str) -> WitnessItem:
    # Decode size
    current_index = 2
    byte_chunk = wi_string[:current_index]
    increment = match_byte_chunk(byte_chunk)
    size = wi_string[current_index:current_index + increment] if increment else byte_chunk
    current_index += increment

    # Get item
    size_int = int(size, 16)
    item = wi_string[current_index:current_index + size_int]

    # Construct WitnessItem
    constructed_witness_item = WitnessItem(item)
    if constructed_witness_item.encoded != size + item:
        raise TypeError("Given input string did not generate same WitnessItem object")
    return constructed_witness_item


class Witness:
    """
    Witness Fields
    =================================================
    |   field           |   size    |   format      |
    =================================================
    |   stack_items     |   var     |   CompactSize |
    =================================================
    |   item1           |   var     |   WitnessItem |
    |   item2           |   var     |   WitnessItem |
    |   ...             |   ...     |   ...         |
    |   itemN           |   var     |   WitnessItem |
    =================================================

    """

    def __init__(self, items: list):
        """
        Input is a list of WitnessItems. We create a witness_dict for each such item.
        """
        # Get count
        num_of_items = len(items)
        self.stack_items = CompactSize(num_of_items).encoded
        self.stack_items_int = num_of_items

        # Get items
        self.witness_items = items

    @property
    def encoded(self):
        witness_string = self.stack_items
        for item in self.witness_items:
            witness_string += item.encoded
        return witness_string

    def to_json(self):
        witness_dict = {
            "stack_items": self.stack_items
        }
        for x in range(self.stack_items_int):
            temp_wi = self.witness_items[x]
            witness_dict.update({
                x: json.loads(temp_wi.to_json())
            })
        return json.dumps(witness_dict, indent=2)


def decode_witness(witness_string: str) -> Witness:
    # Get stack items
    current_index = 2
    byte_chunk = witness_string[:current_index]
    increment = match_byte_chunk(byte_chunk)
    stack_items = witness_string[current_index:current_index + increment] if increment else byte_chunk
    current_index += increment
    stack_items_int = int(stack_items, 16)

    # Get witnesses
    witness_list = []
    for x in range(stack_items_int):
        temp_witness = decode_witness_item(witness_string[current_index:])
        witness_list.append(temp_witness)
        current_index += len(temp_witness.encoded)

    # Construct verification
    constructed_encoding = stack_items
    for witness in witness_list:
        constructed_encoding += witness.encoded

    # Construct witness and verify
    constructed_witness = Witness(items=witness_list)
    if constructed_witness.encoded != constructed_encoding:
        raise TypeError("Given input string did not generate same Witness object")
    return constructed_witness


class Transaction:
    """
    Transaction Fields
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
    VERSION_BYTES = 4
    MARKER_BYTES = 1
    FLAG_BYTES = 1
    LOCKTIME_BYTES = 4
    MARKER = "00"
    FLAG = "01"
    VERSION = 1

    def __init__(self, inputs: list, outputs: list, version=16, witness_list=None, locktime=None):
        """
        We assume the inputs list is not empty.
        """
        # Format version
        self.version = format(version, f"0{2 * self.VERSION_BYTES}x")[::-1]  # Little Endian

        # Get lists
        self.inputs = inputs
        self.outputs = outputs

        # Get size of lists as compactSize elements
        self.num_inputs = CompactSize(len(self.inputs)).encoded
        self.num_outputs = CompactSize(len(self.outputs)).encoded

        # Get witness structure
        self.witness_list = witness_list
        self.segwit = True if self.witness_list else False

        # Set marker and flag
        self.marker = self.MARKER if self.segwit else None
        self.flag = self.FLAG if self.segwit else None

        # Set locktime
        if locktime is None:
            self.locktime = format(0, f"0{2 * self.LOCKTIME_BYTES}x")[::-1]  # Little Endian

    @property
    def encoded(self):
        """
        Return the raw transaction data as hex string
        """
        # Encoded transaction begins with version
        encoded_string = self.version

        # Handle segwit
        segwit = False
        if self.marker and self.flag:
            encoded_string += self.marker + self.flag
            segwit = True

        # Encode inputs
        encoded_string += self.num_inputs
        for input_item in self.inputs:
            encoded_string += input_item.encoded

        # Encode outputs
        encoded_string += self.num_outputs
        for output_item in self.outputs:
            encoded_string += output_item.encoded

        # Handle witness
        if segwit:
            for witness in self.witness_list:
                encoded_string += witness.encoded

        # Locktime
        encoded_string += self.locktime

        return encoded_string

    def to_json(self):
        # Version
        tx_dict = {
            "version": self.version
        }

        # Marker/Flag
        if self.segwit:
            tx_dict.update({
                "marker": "00",
                "flag": "01"
            })

        # Inputs
        input_list = []
        input_count = len(self.inputs)
        for x in range(input_count):
            temp_input = self.inputs[x]
            input_list.append(json.loads(temp_input.to_json()))
        tx_dict.update({
            "input_count": self.num_inputs,
            "inputs": input_list
        })

        # Outputs
        output_list = []
        output_count = len(self.outputs)
        for y in range(output_count):
            temp_output = self.outputs[y]
            output_list.append(json.loads(temp_output.to_json()))
        tx_dict.update({
            "output_count": self.num_outputs,
            "outputs": output_list
        })

        # Witness
        if self.segwit:
            witness_list = []
            witness_count = len(self.witness_list)
            for z in range(witness_count):
                temp_witness = self.witness_list[z]
                witness_list.append(json.loads(temp_witness.to_json()))
            tx_dict.update({
                "witness": witness_list
            })

        # Locktime
        tx_dict.update({
            "locktime": self.locktime
        })

        return json.dumps(tx_dict, indent=2)


def decode_transaction(tx_string: str) -> Transaction:
    # Setup
    current_index = 0
    version_chars = 2 * Transaction.VERSION_BYTES
    marker_chars = 2 * Transaction.MARKER_BYTES
    flag_chars = 2 * Transaction.FLAG_BYTES
    locktime_chars = 2 * Transaction.LOCKTIME_BYTES

    # Version
    version = tx_string[current_index:current_index + version_chars]
    version_int = int(version[::-1], 16)  # Little Endian
    current_index += version_chars

    # Handle segwit
    segwit = False
    marker_check = tx_string[current_index:current_index + marker_chars]
    if marker_check == "00":
        current_index += marker_chars
        flag_check = tx_string[current_index:current_index + flag_chars]
        assert flag_check == "01"
        segwit = True
        current_index += flag_chars

    # Get num inputs
    byte_chunk = tx_string[current_index:current_index + 2]
    current_index += 2
    increment = match_byte_chunk(byte_chunk)
    num_inputs = tx_string[current_index:current_index + increment] if increment else byte_chunk
    current_index += increment
    num_inputs_int = int(num_inputs, 16)

    # Get inputs
    input_list = []
    for x in range(num_inputs_int):
        temp_input = decode_input(tx_string[current_index:])
        input_list.append(temp_input)
        current_index += len(temp_input.encoded)

    # Get num outputs
    byte_chunk = tx_string[current_index:current_index + 2]
    current_index += 2
    increment = match_byte_chunk(byte_chunk)
    num_outputs = tx_string[current_index:current_index + increment] if increment else byte_chunk
    current_index += increment
    num_outputs_int = int(num_outputs, 16)

    # Get outputs
    output_list = []
    for y in range(num_outputs_int):
        temp_output = decode_output(tx_string[current_index:])
        output_list.append(temp_output)
        current_index += len(temp_output.encoded)

    # Get witness
    if segwit:
        witness = decode_witness(tx_string[current_index:])
        current_index += len(witness.encoded)
    else:
        witness = None

    # Get locktime
    locktime = tx_string[current_index:current_index + locktime_chars]
    locktime_int = int(locktime[::-1], 16)  # Little Endian

    # Construct validation
    constructed_encoding = version  # Version
    if segwit:  # Marker and Flag if segwit
        constructed_encoding += "0001"
    constructed_encoding += CompactSize(num_inputs_int)  # Number of inputs
    for t_input in input_list:  # Inputs
        constructed_encoding += t_input.encoded
    constructed_encoding += CompactSize(num_outputs_int)  # Number of outputs
    for t_output in output_list:  # Outputs
        constructed_encoding += t_output.encoded
    if segwit:
        constructed_encoding += witness  # Witness if segwit
    constructed_encoding += locktime

    # Construct Transaction and verify
    witness_list = witness.witness_items if witness else []
    constructed_transaction = Transaction(inputs=input_list, outputs=output_list, witness_list=witness_list,
                                          locktime=locktime_int)
    if constructed_transaction.encoded != constructed_encoding:
        logger.error(f"Constructed transaction: {constructed_transaction.to_json()}")
    return constructed_transaction


# --- TESTING --- #
if __name__ == "__main__":
    hash1 = random_hash256()
    hash2 = random_hash256()
    hash3 = random_hash256()
    rand_int1 = random.randint(1, 100)
    rand_int2 = random.randint(1, 100)
    rand_int3 = random.randint(1, 100)
    default_sequence = 0xFFFFFFFD

    # Create inputs
    input1 = Input(tx_id=hash1, v_out=rand_int1, script_sig=hash2, sequence=default_sequence)
    input2 = Input(tx_id=hash3, v_out=rand_int3, script_sig=hash2, sequence=default_sequence)
    input3 = decode_input(input1.encoded)

    # Create outputs
    output1 = Output(amount=rand_int2, output_script=hash2)
    output2 = decode_output(output1.encoded)

    # Create witnesses
    item1 = WitnessItem(hash1)
    item2 = WitnessItem(hash2)
    item3 = WitnessItem(hash3)
    item4 = decode_witness_item(item1.encoded)
    witness1 = Witness([item1, item2])
    witness2 = Witness([item3, item2])
    witness3 = decode_witness(witness1.encoded)

    # Create Transaction
    tx1 = Transaction(inputs=[input1, input2], outputs=[output1], witness_list=[witness1, witness2])
    print(tx1.to_json())
