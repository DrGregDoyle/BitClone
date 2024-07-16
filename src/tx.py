"""
Refactoring Transaction class

- Transactions are created *without* signature data first.
- Transactions are created for use in TxEngine for signatures
- Inputs unlock UTXOs
- Outputs create UTXOs
"""
import json

from src.library.hash_func import hash256
from src.primitive import ByteOrder, Endian, CompactSize


class Outpoint:
    """
    =========================================================
    |   field       |   byte size   |   format              |
    =========================================================
    |   tx_id       |   32          |   natural byte order  |
    |   v_out       |   4           |   little-endian       |
    =========================================================
    """
    TXID_BYTES = 32
    VOUT_BYTES = 4

    def __init__(self, tx_id: str, v_out: int):
        # tx_id | 32 bytes, natural byte order
        self.tx_id = ByteOrder(tx_id)

        # v_out | 4 bytes, little-endian
        self.v_out = Endian(v_out, length=self.VOUT_BYTES)

    def __repr__(self):
        return self.hex

    @property
    def bytes(self):
        return self.tx_id.bytes + self.v_out.bytes

    @property
    def hex(self):
        return self.bytes.hex()

    def to_json(self):
        outpoint_dict = {
            "tx_id": self.tx_id.hex,
            "v_out": self.v_out.hex
        }
        return json.dumps(outpoint_dict, indent=2)


class UTXO:
    """
    =============================================================
    |   field               |   byte size   |   format          |   db ref
    =============================================================
    |   outpoint            |   36          |   tx_id + v_out   |   key
    -------------------------------------------------------------
    |   height              |   8           |   little-endian   |
    |   amount              |   8           |   little-endian   |
    |   scriptpubkey size   |   var         |   CompactSize     |
    |   scriptpubkey        |   var         |   Script          |
    |   coinbase            |   1           |   boolean         |
    =============================================================
    """
    HEIGHT_BYTES = 8
    AMOUNT_BYTES = 8

    def __init__(self, outpoint: Outpoint, height: int, amount: int, scriptpubkey: str | bytes, coinbase=False):
        # outpoint
        self.outpoint = outpoint

        # height | 8 bytes, little-endian
        self.height = Endian(height, length=self.HEIGHT_BYTES)

        # amount | 8 bytes, little-endian
        self.amount = Endian(amount, length=self.AMOUNT_BYTES)

        # coinbase
        self.coinbase = "01" if coinbase else "00"

        # locking_code and locking_code_size
        self.scriptpubkey = bytes.fromhex(scriptpubkey) if isinstance(scriptpubkey, str) else scriptpubkey
        self.scriptpubkey_size = CompactSize(len(self.scriptpubkey))

    @property
    def key(self):
        return self.outpoint.hex

    @property
    def value(self):
        return self.height.hex + self.coinbase + self.amount.hex + self.scriptpubkey_size.hex + self.scriptpubkey.hex()

    @property
    def bytes(self):
        return self.outpoint.bytes + bytes.fromhex(self.value)

    @property
    def hex(self):
        return self.bytes.hex()

    def to_json(self):
        utxo_dict = {
            "outpoint": json.loads(self.outpoint.to_json()),
            "height": self.height.hex,
            "coinbase": self.coinbase,
            "amount": self.amount.hex,
            "scriptpubkey_size": self.scriptpubkey_size.hex,
            "scriptpubkey": self.scriptpubkey.hex()
        }
        return json.dumps(utxo_dict, indent=2)


class WitnessItem:
    """
    =========================================
    |   field   |   size    |   format      |
    =========================================
    |   size    |   var     |   CompactSize |
    |   item    |   var     |   Script      |
    =========================================
    """

    def __init__(self, item: str | bytes):
        # Get item in bytes
        self.item = bytes.fromhex(item) if isinstance(item, str) else item

        # Get byte size
        self.size = CompactSize(len(self.item))

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
    |   outpoint        |   36          |   tx_id + v_out   |
    |   scriptsig_size  |   var         |   CompactSize     |
    |   scriptsig       |   var         |   Script          |
    |   sequence        |   4 bytes     |   little endian   |
    =========================================================
    """
    SEQUENCE_BYTES = 4

    def __init__(self, outpoint: Outpoint, scriptsig: str | bytes, sequence: int = 0):
        self.outpoint = outpoint
        self.scriptsig = bytes.fromhex(scriptsig) if isinstance(scriptsig, str) else scriptsig
        self.scriptsig_size = CompactSize(len(self.scriptsig))
        self.sequence = Endian(sequence, length=self.SEQUENCE_BYTES)

    @property
    def bytes(self):
        return self.outpoint.bytes + self.scriptsig_size.bytes + self.scriptsig + self.sequence.bytes

    @property
    def hex(self):
        return self.bytes.hex()

    def to_json(self):
        input_dict = {
            "tx_id": self.outpoint.tx_id.hex,
            "v_out": self.outpoint.v_out.hex,
            "scriptsig_size": self.scriptsig_size.hex,
            "scriptsig": self.scriptsig.hex(),
            "sequence": self.sequence.hex
        }
        return json.dumps(input_dict, indent=2)


class TxOutput:
    """
    =============================================================
    |   field             |   byte size   |   format          |
    =============================================================
    |   amount            |   8           |   little-endian   |
    |   scriptpubkey_size |   var         |   CompactSize     |
    |   scriptpubkey      |   var         |   Script          |
    =============================================================
    """
    AMOUNT_BYTES = 8

    def __init__(self, amount: int, scriptpubkey: str | bytes):
        self.amount = Endian(amount, length=self.AMOUNT_BYTES)
        _scriptpubkey = bytes.fromhex(scriptpubkey) if isinstance(scriptpubkey, str) else scriptpubkey
        self.scriptpubkey_size = CompactSize(len(_scriptpubkey))
        self.scriptpubkey = _scriptpubkey

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
        |   sighash     |   4               |   little-endian
        =========================================================
    """
    VERSION_BYTES = 4
    LOCKTIME_BYTES = 4
    SIGHASH_BYTES = 4

    def __init__(self, inputs: list, outputs: list, version=1, locktime=0, sighash=1, witness=None):
        # Version, locktime, sighash | 4 bytes, little-endian
        self.version = Endian(version, length=self.VERSION_BYTES)
        self.locktime = Endian(locktime, length=self.LOCKTIME_BYTES)
        self.sighash = Endian(sighash, length=self.SIGHASH_BYTES)

        # Inputs
        self.input_count = CompactSize(len(inputs))
        self.inputs = inputs

        # Outputs
        self.output_count = CompactSize(len(outputs))
        self.outputs = outputs

        # Get Witness details
        self.segwit = False if witness is None else True
        self.witness = [] if witness is None else witness

    @property
    def bytes(self):
        # Version
        tx_bytes = self.version.bytes

        # Marker/Flag
        if self.segwit:
            tx_bytes += bytes(b"0001")  # Marker/Flag hardcoded

        # Inputs
        tx_bytes += self.input_count.bytes + self._byte_list(self.inputs)

        # Outputs
        tx_bytes += self.output_count.bytes + self._byte_list(self.outputs)

        # Witness
        if self.segwit:
            tx_bytes += self._byte_list(self.witness)

        # Locktime
        tx_bytes += self.locktime.bytes

        # Sighash
        tx_bytes += self.sighash.bytes

        return tx_bytes

    @property
    def hex(self):
        return self.bytes.hex()

    @property
    def txid(self):
        return hash256(self._get_data())

    @property
    def wtxid(self):
        return hash256(self.bytes)

    @property
    def size(self):
        return len(self.bytes)

    @property
    def weight(self):
        total = 0
        if self.segwit:
            # Multiply marker, flag and witness by 1
            total += len(self._byte_list(self.witness)) + 2  # Marker/Flag is 2 bytes | 4 chars
            # Multiply everything else by 4
            total += 4 * (len(self.input_count.bytes) + len(self._byte_list(self.inputs)) + len(self.version.bytes) +
                          len(self.output_count.bytes) + len(self._byte_list(self.outputs)) + len(self.locktime.bytes))
        else:
            total = self.size * 4
        return total

    @property
    def vbytes(self):
        return self.weight / 4

    def _byte_list(self, obj_list: list):
        total = bytes()
        for b in obj_list:
            total += b.bytes
        return total

    def _get_data(self):
        if self.segwit:
            data = (self.version.bytes + self.input_count.bytes + self._byte_list(self.inputs) +
                    self.output_count.bytes + self._byte_list(self.outputs) + self.locktime.bytes)
        else:
            data = self.bytes
        return data

    def to_json(self):
        # ID | IDs are displayed in natural byte order
        tx_dict = {"txid": self.txid, "wtxid": self.wtxid}

        # Version
        tx_dict.update({"version": self.version.hex})

        # Marker/Flag
        if self.segwit:
            tx_dict.update({"marker": "00", "flag": "01"})

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

        # Sighash
        tx_dict.update({"sighash": self.sighash.hex})

        return json.dumps(tx_dict, indent=2)


# --- TESTING

"""
{
  "version": "01000000",
  "input_count": "02",
  "inputs": [
    {
      "tx_id": "fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f",
      "v_out": "00000000",
      "scriptsig_size": "00",
      "scriptsig": "",
      "sequence": "eeffffff"
    },
    {
      "tx_id": "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a",
      "v_out": "01000000",
      "scriptsig_size": "00",
      "scriptsig": "",
      "sequence": "ffffffff"
    }
  ],
  "output_count": "02",
  "outputs": [
    {
      "amount": "202cb20600000000",
      "scriptpubkey_size": "19",
      "scriptpubkey": "76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac"
    },
    {
      "amount": "9093510d00000000",
      "scriptpubkey_size": "19",
      "scriptpubkey": "76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac"
    }
  ],
  "locktime": "11000000",
  "sighash": "01000000"
}
"""
if __name__ == "__main__":
    _outpt1 = Outpoint(tx_id="fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f", v_out=0)
    _outpt2 = Outpoint(tx_id="ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a", v_out=1)
    _seq1 = int("eeffffff", 16)
    _seq2 = int("ffffffff", 16)
    input1 = TxInput(_outpt1, scriptsig="", sequence=_seq1)
    input2 = TxInput(_outpt2, scriptsig="", sequence=_seq2)

    _amount1 = int("202cb20600000000", 16)
    _amount2 = int("9093510d00000000", 16)
    scriptpubkey1 = "76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac"
    scriptpubkey2 = "76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac"
    output1 = TxOutput(amount=_amount1, scriptpubkey=scriptpubkey1)
    output2 = TxOutput(amount=_amount2, scriptpubkey=scriptpubkey2)

    _locktime = 0x11
    _sighash = 1
    tx = Transaction(inputs=[input1, input2], outputs=[output1, output2], locktime=_locktime, sighash=_sighash)
