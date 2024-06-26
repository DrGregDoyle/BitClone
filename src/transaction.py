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

from src.encoder_lib import encode_compact_size, encode_byte_format, WEIGHT_UNIT_DICT, hash256

# --- LOGGING --- #
log_level = logging.DEBUG
logger = logging.getLogger(__name__)
logger.setLevel(log_level)
logger.addHandler(logging.StreamHandler(stream=sys.stdout))


# --- CLASSES --- #
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
        self.stack_items = encode_compact_size(len(items))

        # Get items
        self.witness_items = items

    @property
    def encoded(self):
        witness_string = self.stack_items
        for item in self.witness_items:
            witness_string += item.encoded
        return witness_string

    def to_json(self):
        witness_dict = {"stack_items": self.stack_items}
        for x in range(len(self.witness_items)):
            temp_wi = self.witness_items[x]
            witness_dict.update({x: json.loads(temp_wi.to_json())})
        return json.dumps(witness_dict, indent=2)


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
    |   witness         |   var         |   Witness.encoded |
    =========================================================
    """
    HASH_CHARS = 64

    def __init__(self, tx_id: str, v_out: int, script_sig: str, sequence: int, witness=None):
        # tx_id
        self.tx_id = tx_id.zfill(self.HASH_CHARS)

        # v_out - little endian
        self.v_out = encode_byte_format(v_out, "v_out", internal=True)

        # script_sig and script_sig_size
        self.script_sig = script_sig
        self.script_sig_size = encode_compact_size(len(self.script_sig))

        # sequence
        self.sequence = encode_byte_format(sequence, "sequence", internal=True)

        # witness
        self.witness = witness

    def __eq__(self, other):
        return self.encoded == other.encoded

    @property
    def segwit(self):
        return True if self.witness else False

    @property
    def encoded(self):
        return self.tx_id + self.v_out + self.script_sig_size + self.script_sig + self.sequence

    @property
    def witness_encoded(self):
        encoded_string = ""
        if self.segwit:
            encoded_string = self.witness.encoded
        return encoded_string

    def to_json(self):
        input_dict = {
            "tx_id": self.tx_id,
            "v_out": self.v_out,
            "script_sig_size": self.script_sig_size,
            "script_sig": self.script_sig,
            "sequence": self.sequence,
        }
        if self.segwit:
            input_dict.update({"witness": json.loads(self.witness.to_json())})
        return json.dumps(input_dict, indent=2)

    def add_witness(self, witness: Witness):
        if self.witness is None:
            self.witness = witness


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
    NOTE: Created outputs will get added to UTXO DB
    """
    AMOUNT_BYTES = 8

    def __init__(self, amount: int, output_script: str):
        # amount - little endian
        self.amount = encode_byte_format(amount, "amount", internal=True)

        # script and script size
        self.script_pub_key = output_script
        self.script_pub_key_size = encode_compact_size(len(self.script_pub_key))

    @property
    def encoded(self):
        return self.amount + self.script_pub_key_size + self.script_pub_key

    def to_json(self):
        output_dict = {
            "amount": self.amount,
            "script_pub_key_size": self.script_pub_key_size,
            "script_pub_key": self.script_pub_key
        }
        return json.dumps(output_dict, indent=2)


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
    MARKER = "00"
    FLAG = "01"

    def __init__(self, inputs: list, outputs: list, locktime=None, version=16):
        """
        We assume the inputs list is not empty.
        """
        # version - little endian
        self.version = encode_byte_format(version, "version", internal=True)

        # Get lists
        self.inputs = inputs
        self.outputs = outputs

        # Get size of lists as compactSize elements
        self.input_count = encode_compact_size(len(self.inputs))
        self.output_count = encode_compact_size(len(self.outputs))

        # Check segwit - handle malformed transaction
        segwit_list = [i.segwit for i in self.inputs]
        self.segwit = all(segwit_list)
        if not self.segwit and True in segwit_list:
            raise TypeError("All inputs must have a witness.")

        # Witness
        self.witness_list = [i.witness for i in self.inputs] if self.segwit else []
        self.marker = self.MARKER if self.segwit else None
        self.flag = self.FLAG if self.segwit else None

        # locktime - little endian
        if locktime is None:
            locktime = 0
        self.locktime = encode_byte_format(locktime, "locktime", internal=True)

    @property
    def encoded(self):
        """
        Return the raw transaction data as hex string
        """
        # Encoded transaction begins with version
        encoded_string = self.version

        # Handle segwit
        if self.segwit:
            encoded_string += self.marker + self.flag

        # Encode inputs
        encoded_string += self.input_count + self._encoded_list(self.inputs)

        # Encode outputs
        encoded_string += self.output_count + self._encoded_list(self.outputs)

        # Handle witness
        if self.segwit:
            encoded_string += self._encoded_list(self.witness_list)

        # Locktime
        encoded_string += self.locktime

        return encoded_string

    @property
    def byte_size(self):
        return len(self.encoded) // 2

    @property
    def weight(self):
        # Legacy
        if not self.segwit:
            return self.byte_size * 4

        # Divide number of hex chars by 2 and multiply by WEIGHT_UNIT_DICT factor, for each field
        total = 0
        total += (len(self.version) // 2) * WEIGHT_UNIT_DICT.get("version")
        total += (len(self.marker) // 2) * WEIGHT_UNIT_DICT.get("marker")
        total += (len(self.flag) // 2) * WEIGHT_UNIT_DICT.get("flag")
        total += (len(self.input_count) + len(self._encoded_list(self.inputs)) // 2) * WEIGHT_UNIT_DICT.get("input")
        total += (len(self.output_count) + len(self._encoded_list(self.outputs)) // 2) * WEIGHT_UNIT_DICT.get("output")
        total += (len(self._encoded_list(self.witness_list)) // 2) * WEIGHT_UNIT_DICT.get("witness")
        total += (len(self.locktime) // 2) * WEIGHT_UNIT_DICT.get("locktime")

        return total

    @property
    def vbytes(self):
        if not self.segwit:
            return self.byte_size
        else:
            return self.weight / 4

    @property
    def id(self):
        if self.segwit:
            unhashed_data = self.version + self.input_count + self._encoded_list(
                self.inputs) + self.output_count + self._encoded_list(self.outputs) + self.locktime
        else:
            unhashed_data = self.encoded
        return hash256(unhashed_data)

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
            "input_count": self.input_count,
            "inputs": input_list
        })

        # Outputs
        output_list = []
        output_count = len(self.outputs)
        for y in range(output_count):
            temp_output = self.outputs[y]
            output_list.append(json.loads(temp_output.to_json()))
        tx_dict.update({
            "output_count": self.output_count,
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

    def _encoded_list(self, item_list: list):
        encoded_string = ""
        for item in item_list:
            encoded_string += item.encoded
        return encoded_string
