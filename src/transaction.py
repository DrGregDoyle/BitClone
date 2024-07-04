"""
Transactions
"""
import json

from src.compact_size import CompactSize
from src.cryptography import hash256, reverse_bytes


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
        # Item | hex string or bytes object
        self.item = bytes.fromhex(item) if isinstance(item, str) else item

        # Size
        item_length = len(self.item)
        self.size = CompactSize(item_length)

    @property
    def bytes(self):
        return self.size.bytes + self.item

    @property
    def hex(self):
        return self.bytes.hex()

    def to_json(self):
        witness_item_dict = {
            "size": self.size.hex,
            "item": self.item.hex()
        }
        return json.dumps(witness_item_dict, indent=2)


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
    SEQUENCE = 0x00
    TX_ID_BYTES = 32
    V_OUT_BYTES = 4
    SEQUENCE_BYTES = 4

    def __init__(self, tx_id: str | bytes, v_out: int | bytes, scriptsig: str | bytes,
                 sequence: int | bytes = SEQUENCE):
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
        self.sequence = sequence.to_bytes(length=self.SEQUENCE_BYTES, byteorder="little") if isinstance(sequence,
                                                                                                        int) else sequence

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
        self.amount = amount.to_bytes(length=self.AMOUNT_BYTES, byteorder="little") if isinstance(amount,
                                                                                                  int) else amount

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
    VERSION = 2
    LOCKTIME = 0
    VERSION_BYTES = 4
    MARKER = bytes.fromhex("00")
    FLAG = bytes.fromhex("01")
    LOCKTIME_BYTES = 4

    def __init__(self, inputs: list, outputs: list, witness: list | None = None, locktime: int | bytes = LOCKTIME,
                 version: int | bytes = VERSION):
        """
        inputs: list of TxInput objects
        outputs: list of TxOutput objects
        witness: list of Witness objects
        """
        # Version
        self.version = version.to_bytes(length=self.VERSION_BYTES, byteorder="little") \
            if isinstance(version, int) else version

        # Locktime
        self.locktime = locktime.to_bytes(length=self.LOCKTIME_BYTES, byteorder="little") \
            if isinstance(locktime, int) else locktime

        # Inputs
        input_num = len(inputs)
        self.input_count = CompactSize(input_num)
        self.inputs = inputs

        # Outputs
        output_num = len(outputs)
        self.output_count = CompactSize(output_num)
        self.outputs = outputs

        # Witness/Segwit
        self.segwit = False
        self.witness = []
        if witness:
            self.segwit = True
            self.witness = [w for w in witness]

    @property
    def bytes(self):
        # Version
        tx_bytes = self.version

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
        tx_bytes += self.locktime
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
                self.output_bytes) + len(self.version) + len(self.locktime))
        else:
            total = self.size * 4
        return total

    @property
    def vbytes(self):
        return self.weight / 4

    @property
    def txid(self):
        if self.segwit:
            data = (self.version + self.input_count.bytes + self.input_bytes + self.output_count.bytes +
                    self.output_bytes + self.locktime).hex()
        else:
            data = self.bytes.hex()
        return hash256(data)

    def to_json(self):
        # ID
        tx_dict = {
            "txid": reverse_bytes(self.txid).hex()
        }

        # Version
        tx_dict.update({
            "version": self.version.hex()
        })

        # Marker/Flag
        if self.segwit:
            tx_dict.update({
                "marker": self.MARKER.hex(),
                "flag": self.FLAG.hex()
            })

        # Inputs
        tx_dict.update({
            "input_count": self.input_count.hex,
            "inputs": [json.loads(i.to_json()) for i in self.inputs]
        })

        # Outputs
        tx_dict.update({
            "output_count": self.output_count.hex,
            "outputs": [json.loads(t.to_json()) for t in self.outputs]
        })

        # Witness
        if self.segwit:
            tx_dict.update({
                "witness": [json.loads(w.to_json()) for w in self.witness]
            })

        # Locktime
        tx_dict.update({
            "locktime": self.locktime.hex()
        })
        return json.dumps(tx_dict, indent=2)

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


# --- TESTING
if __name__ == "__main__":
    pass
