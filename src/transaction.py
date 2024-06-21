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

from src.encoder_lib import encode_compact_size

# --- LOGGING --- #
log_level = logging.DEBUG
logger = logging.getLogger(__name__)
logger.setLevel(log_level)
logger.addHandler(logging.StreamHandler(stream=sys.stdout))


# --- CLASSES --- #


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

    def __init__(self, tx_id: str, v_out: int, script_sig: str, sequence: int):
        # Format tx_id
        self.tx_id = tx_id.zfill(2 * self.TX_BYTES)

        # Little endian format for v_out and sequence
        self.v_out = format(v_out, f"0{2 * self.INDEX_BYTES}x")[::-1]
        self.sequence = format(sequence, f"0{2 * self.SEQUENCE_BYTES}x")[::-1]

        # Get script and script_size
        self.script_sig = script_sig
        self.script_sig_size = encode_compact_size(len(self.script_sig))

    def __eq__(self, other):
        return self.encoded == other.encoded

    @property
    def encoded(self):
        return self.tx_id + self.v_out + self.script_sig_size + self.script_sig + self.sequence

    @property
    def v_out_int(self):
        return int(self.v_out[::-1], 16)

    def outpoint(self):
        return self.tx_id + self.v_out

    def to_json(self):
        input_dict = {
            "tx_id": self.tx_id,
            "v_out": self.v_out,
            "script_sig_size": self.script_sig_size,
            "script_sig": self.script_sig,
            "sequence": self.sequence
        }
        return json.dumps(input_dict, indent=2)


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
        self.script_pub_key_size = encode_compact_size(len(self.script_pub_key))

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
        self.size = encode_compact_size(len(item))
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
        self.stack_items = encode_compact_size(num_of_items)
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
        self.num_inputs = encode_compact_size(len(self.inputs))
        self.num_outputs = encode_compact_size(len(self.outputs))

        # Get witness structure
        self.witness_list = witness_list
        self.segwit = True if self.witness_list else False

        # Set marker and flag
        self.marker = self.MARKER if self.segwit else None
        self.flag = self.FLAG if self.segwit else None

        # Set locktime
        if locktime is None:
            self.locktime = format(0, f"0{2 * self.LOCKTIME_BYTES}x")[::-1]  # Little Endian
        else:
            self.locktime = format(locktime, f"0{2 * self.LOCKTIME_BYTES}x")[::-1]

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
