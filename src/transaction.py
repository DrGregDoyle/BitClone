"""
Transactions
"""
import json

from src.library.hash_func import hash256
from src.parse import reverse_bytes
from src.predicates import CompactSize, ByteOrder, Endian


class WitnessItem:
    """
    =========================================
    |   field   |   size    |   format      |
    =========================================
    |   size    |   var     |   CompactSize |
    |   item    |   var     |   bytes       |
    =========================================
    """

    def __init__(self, item: str | bytes):
        # Get bytes
        data = bytes.fromhex(item) if isinstance(item, str) else item

        # Get byte size
        self.size = CompactSize(len(data))

        # Get item
        self.item = data

    @property
    def bytes(self):
        return self.size.bytes + self.item

    @property
    def hex(self):
        return self.bytes.hex()

    def to_json(self):
        witness_item_dict = {"size": self.size.hex, "item": self.item.hex()}
        return json.dumps(witness_item_dict, indent=2)


class Witness:
    """
    =============================================
    |   field       |   size    |   format      |
    =============================================
    |   stack_items |   var     |   CompactSize |
    |   items       |   var     |   WitnessItem |
    =============================================
    """

    def __init__(self, items: list):
        # list of WitnessItem objects
        self.items = items

        # Get stack_items
        self.stack_items = CompactSize(len(self.items))

    @property
    def bytes(self):
        """
        Get the byte encoding of all elements of the witness.
        """
        return self.stack_items.bytes + bytes().join([i.bytes for i in self.items])

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
    SEQUENCE = 0
    TX_ID_BYTES = 32
    V_OUT_BYTES = 4
    SEQUENCE_BYTES = 4

    def __init__(self, tx_id: str | bytes, v_out: int, scriptsig: str | bytes,
                 sequence: int = SEQUENCE):
        """
        We assume that the input variables will always be in either "big-endian" or "reverse byte order",
        depending on the variable.
        """
        # tx_id | 32 bytes
        self.tx_id = ByteOrder(tx_id)

        # v_out | 4 bytes
        self.v_out = Endian(v_out, self.V_OUT_BYTES)

        # scriptsigsize | CompactSize || scriptsig | n bytes
        self.scriptsig = bytes.fromhex(scriptsig) if isinstance(scriptsig, str) else scriptsig
        self.scriptsig_size = CompactSize(len(self.scriptsig))

        # sequence | 4 bytes
        self.sequence = Endian(sequence, self.SEQUENCE_BYTES)

    @property
    def bytes(self):
        return self.tx_id.bytes + self.v_out.bytes + self.scriptsig_size.bytes + self.scriptsig + self.sequence.bytes

    @property
    def hex(self):
        return self.bytes.hex()

    def to_json(self):
        input_dict = {
            "tx_id": self.tx_id.hex,
            "v_out": self.v_out.hex,
            "scriptsig_size": self.scriptsig_size.hex,
            "scriptsig": self.scriptsig.hex(),
            "sequence": self.sequence.hex
        }
        return json.dumps(input_dict, indent=2)


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

    def __init__(self, amount: int, scriptpubkey: str | bytes):
        # amount | 8 bytes
        self.amount = Endian(amount, byte_size=self.AMOUNT_BYTES)

        # scriptpubkey
        self.scriptpubkey = bytes.fromhex(scriptpubkey) if isinstance(scriptpubkey, str) else scriptpubkey
        self.scriptpubkey_size = CompactSize(len(self.scriptpubkey))

    @property
    def bytes(self):
        return self.amount.bytes + self.scriptpubkey_size.bytes + self.scriptpubkey

    @property
    def hex(self):
        return self.bytes.hex()

    def to_json(self):
        output_dict = {
            "amount": self.amount.hex,
            "scriptpubkey_size": self.scriptpubkey_size.hex,
            "scriptpubkey": self.scriptpubkey.hex()
        }
        return json.dumps(output_dict, indent=2)


class Transaction:
    """
    =========================================================
    |   field       |   size            |   format          |
    =========================================================
    |   version     |   4               |   little-endian   |
    |   marker      |   1 (optional)    |   fixed           |
    |   flag        |   1 (optional)    |   fixed           |
    |   num_input   |   var             |   CompactSize     |
    |   inputs      |   var             |   [TxInput]       |
    |   num_output  |   var             |   CompactSize     |
    |   outputs     |   var             |   [TxOutput]      |
    |   witness     |   optional        |   [Witness}       |
    |   locktime    |   4               |   little-endian   |
    =========================================================
    """
    VERSION = 2
    MARKER = bytes.fromhex("00")
    FLAG = bytes.fromhex("01")
    LOCKTIME = 0

    VERSION_BYTES = 4
    LOCKTIME_BYTES = 4
    TXID_BYTES = 32

    def __init__(self, inputs: list, outputs: list, witness: list | None = None, locktime: int = LOCKTIME,
                 version: int = VERSION):
        """
        inputs: list of TxInput objects
        outputs: list of TxOutput objects
        witness: list of Witness objects
        """
        # Version, locktime | 4 bytes
        self.version = Endian(version, self.VERSION_BYTES)
        self.locktime = Endian(locktime, self.LOCKTIME_BYTES)

        # Inputs
        self.input_count = CompactSize(len(inputs))
        self.inputs = inputs

        # Outputs
        self.output_count = CompactSize(len(outputs))
        self.outputs = outputs

        # Witness/Segwit
        self.segwit = False
        self.witness = []
        if witness:
            self.segwit = True
            self.witness = [w for w in witness]

        # TxID
        if self.segwit:
            data = (self.version.bytes + self.input_count.bytes + self.input_bytes + self.output_count.bytes +
                    self.output_bytes + self.locktime.bytes)
        else:
            data = self.bytes

        # txid | data is given in natural byte order
        self.txid = hash256(data)

        # wtxid
        self.wtxid = hash256(self.bytes)  # will be equal to txid if no segwit

    @property
    def reverse_byte_order(self):
        return ByteOrder(self.txid).hex

    @property
    def bytes(self):
        # Version
        tx_bytes = self.version.bytes

        # Marker/Flag
        if self.segwit:
            tx_bytes += self.MARKER + self.FLAG

        # Inputs
        tx_bytes += self.input_count.bytes + self.input_bytes

        # Outputs
        tx_bytes += self.output_count.bytes + self.output_bytes

        # Witness
        if self.segwit:
            tx_bytes += self.witness_bytes

        # Locktime
        tx_bytes += self.locktime.bytes
        return tx_bytes

    @property
    def hex(self):
        return self.bytes.hex()

    @property
    def size(self):
        return len(self.bytes)

    @property
    def weight(self):
        total = 0
        if self.segwit:
            # Multiply marker, flag and witness by 1
            total += len(self.witness_bytes) + len(self.MARKER) + len(self.FLAG)
            # Multiply everything else by 4
            total += 4 * (len(self.input_count.bytes) + len(self.input_bytes) + len(self.output_count.bytes) + len(
                self.output_bytes) + len(self.version.bytes) + len(self.locktime.bytes))
        else:
            total = self.size * 4
        return total

    @property
    def vbytes(self):
        return self.weight / 4

    @property
    def input_bytes(self):
        _input_bytes = bytes()
        for i in self.inputs:
            _input_bytes += i.bytes
        return _input_bytes

    @property
    def output_bytes(self):
        _output_bytes = bytes()
        for i in self.outputs:
            _output_bytes += i.bytes
        return _output_bytes

    @property
    def witness_bytes(self):
        _witness_bytes = bytes()
        for i in self.witness:
            _witness_bytes += i.bytes
        return _witness_bytes

    def to_json(self):
        # ID | IDs are displayed in reverse byte order
        tx_dict = {"txid": reverse_bytes(self.txid), "wtxid": reverse_bytes(self.wtxid)}

        # Version
        tx_dict.update({"version": self.version.hex})

        # Marker/Flag
        if self.segwit:
            tx_dict.update({"marker": self.MARKER.hex(), "flag": self.FLAG.hex()})

        # Inputs
        tx_dict.update({"input_count": self.input_count.hex, "inputs": [json.loads(i.to_json()) for i in self.inputs]})

        # Outputs
        tx_dict.update(
            {"output_count": self.output_count.hex, "outputs": [json.loads(t.to_json()) for t in self.outputs]})

        # Witness
        if self.segwit:
            tx_dict.update({"witness": [json.loads(w.to_json()) for w in self.witness]})

        # Locktime
        tx_dict.update({"locktime": self.locktime.hex})
        return json.dumps(tx_dict, indent=2)


# -- TESTING
if __name__ == "__main__":
    pass
