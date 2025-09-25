"""
The classes for BitClone transactions
"""
from io import SEEK_CUR

from src.core import Serializable, SERIALIZED, get_stream, read_little_int, read_stream, TX
from src.cryptography import hash256
from src.data import read_compact_size, write_compact_size

__all__ = ["TxInput", "TxOutput", "WitnessField", "Transaction"]

# --- CACHE KEYS --- #
SEGWIT_KEY = "is_segwit"
TXID_KEY = "txid"
WTXID_KEY = "wtxid"
WU_KEY = "weight_units"
VB_KEY = "virtual_bytes"


class TxInput(Serializable):
    """
    TxInput
    -------------------------------------------------------------
    |   Field           |   Byte Size   |   Format              |
    -------------------------------------------------------------
    |   txid            |   32          |   natural byte order  |
    |   vout            |   4           |   little-endian       |
    |   scriptsig_size  |   var         |   CompactSize         |
    |   scriptsig       |   var         |   Script              |
    |   sequence        |   4           |   little-endian       |
    -------------------------------------------------------------
    """
    __slots__ = ("txid", "vout", "scriptsig", "sequence")

    def __init__(self, txid: bytes, vout: int | bytes, scriptsig: bytes, sequence: int | bytes):
        self.txid = txid
        self.vout = vout if isinstance(vout, int) else int.from_bytes(vout, "little")
        self.scriptsig = scriptsig
        self.sequence = sequence if isinstance(sequence, int) else int.from_bytes(sequence, "little")

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        txid = read_stream(stream, TX.TXID, "txid")
        vout = read_little_int(stream, TX.VOUT, "vout")
        scriptsig_size = read_compact_size(stream)
        scriptsig = read_stream(stream, scriptsig_size, "scriptsig")
        sequence = read_little_int(stream, TX.SEQUENCE, "sequence")

        return cls(txid, vout, scriptsig, sequence)

    def to_bytes(self) -> bytes:
        """
        Serialize input
        txid || vout || scriptsig_size || scriptsig || sequence
        """
        parts = [
            self.txid,
            self.vout.to_bytes(TX.VOUT, "little"),
            write_compact_size(len(self.scriptsig)),
            self.scriptsig,
            self.sequence.to_bytes(TX.SEQUENCE, "little")
        ]
        return b''.join(parts)

    def to_dict(self) -> dict:
        return {
            "txid": self.txid.hex(),
            "vout": self.vout,
            "scriptsig_size": len(self.scriptsig),
            "scriptsig": self.scriptsig.hex(),
            "sequence": self.sequence
        }


class TxOutput(Serializable):
    """
    TxInput
    -----------------------------------------------------------------
    |   Field               |   Byte Size   |   Format              |
    -----------------------------------------------------------------
    |   Amount              |   8           |   little-endian       |
    |   scriptpubkey_size   |   var         |   CompactSize         |
    |   scriptpubkey        |   var         |   Script              |
    -----------------------------------------------------------------
    """
    __slots__ = ("amount", "scriptpubkey")

    def __init__(self, amount: int | bytes, scriptpubkey: bytes):
        self.amount = amount if isinstance(amount, int) else int.from_bytes(amount, "little")
        self.scriptpubkey = scriptpubkey

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        amount = read_little_int(stream, TX.AMOUNT, "amount")
        scriptpubkey_size = read_compact_size(stream)
        scriptpubkey = read_stream(stream, scriptpubkey_size, "scriptpubkey")

        return cls(amount, scriptpubkey)

    def to_bytes(self) -> bytes:
        """
        Serializt the TxOutput
        amount || scriptpubkey_size || scriptpubkey
        """
        parts = [
            self.amount.to_bytes(TX.AMOUNT, "little"),
            write_compact_size(len(self.scriptpubkey)),
            self.scriptpubkey
        ]
        return b''.join(parts)

    def to_dict(self) -> dict:
        return {
            "amount": self.amount,
            "scriptpubkey_size": len(self.scriptpubkey),
            "scriptpubkey": self.scriptpubkey.hex()
        }


class WitnessField(Serializable):
    """
    WitnessField
    -------------------------------------------------------------
    |   Field           |   Byte Size   |   Format              |
    -------------------------------------------------------------
    |   Stack Items     |   var         |   CompactSize         |
    =============================================================
    |   Size            |   var         |   CompactSize         |
    |   Item            |   var         |   bytes               |
    =============================================================
    |   the Size | Item format repeats for all witness items    |
    -------------------------------------------------------------    
    """
    __slots__ = ("items",)

    def __init__(self, items: list | bytes):
        self.items = items if isinstance(items, list) else [items]

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # Number of stack items
        stack_items = read_compact_size(stream)

        # Get items
        witness_items = []
        for _ in range(stack_items):
            item_len = read_compact_size(stream)
            witness_items.append(read_stream(stream, item_len, "WitnessField item"))
        return cls(witness_items)

    def to_bytes(self) -> bytes:
        """
        Serialize the stack items
        """
        parts = [write_compact_size(len(self.items))]
        for item in self.items:
            parts.append(write_compact_size(len(item)))
            parts.append(item)
        return b''.join(parts)

    def to_dict(self) -> dict:
        witness_dict = {
            "stack_items": len(self.items)
        }
        for x in range(len(self.items)):
            temp_item = self.items[x]
            witness_dict.update({
                x: {
                    "size": len(temp_item),
                    "item": temp_item.hex()
                }
            })
        return witness_dict


class Transaction(Serializable):
    """
    Transaction
    -------------------------------------------------------------
    |   Field           |   Byte Size   |   Format              |
    -------------------------------------------------------------
    |   Version         |   4           |   little-endian       |
    |   Marker*         |   1           |   fixed byte          |
    |   Flag*           |   1           |   fixed byte          |
    |   input_count     |   var         |   ComapctSize         |
    |   inputs          |   var         |   TxInput             |
    |   output_count    |   var         |   CompactSize         |
    |   outputs         |   var         |   TxOutput            |
    |   witness*        |   var         |   WitnessField             |
    |   locktime        |   4           |   little-endian       |
    -------------------------------------------------------------
    * indicates optional segwit specific fields
    """
    __slots__ = ("version", "inputs", "outputs", "locktime", "witness", "_cache")

    def __init__(self, inputs: list[TxInput] = None, outputs: list[TxOutput] = None, witness: list[WitnessField] = None,
                 locktime: int = 0, version: int = TX.BIP68):
        self.inputs = inputs or []
        self.outputs = outputs or []
        self.witness = witness or []
        self.version = version
        self.locktime = locktime
        self._cache = {}  # Internal dict for future values

    def _update_cache(self):
        """
        Run those functions which contribute to the _cache dict
        """
        _ = self.is_segwit
        _ = self.txid

    def _invalidate_cache(self):
        """
        Remove all cache values
        """
        self._cache = {}

    def _get_txid_preimage(self) -> bytes:
        """
        For a given transaction, return what will need to be hashed to yield the tx id
        For segwit, this is the formatted version, inputs, outpus and locktiem
        For non-segwit this is the serialized tx itself
        """
        if self.is_segwit:
            parts = [
                self.version.to_bytes(TX.VERSION, "little"),
                self._get_input_bytes(),
                self._get_output_bytes(),
                self.locktime.to_bytes(TX.LOCKTIME, "little")
            ]
            return b''.join(parts)

        # Legacy TX
        return self.to_bytes()

    def _get_wtxid_preimage(self) -> bytes:
        if self.is_segwit:
            parts = [
                self.version.to_bytes(TX.VERSION, "little"),
                b'\x00\x01',  # Marker\Flag
                self._get_input_bytes(),
                self._get_output_bytes(),
                self.locktime.to_bytes(TX.LOCKTIME, "little"),
                self._get_witness_bytes()
            ]
            return b''.join(parts)
        # Legacy TX
        return self.to_bytes()

    def _get_input_bytes(self) -> bytes:
        """
        Returns the serialized inputs, including input_num
        """
        input_num = len(self.inputs)
        return write_compact_size(input_num) + b''.join([i.to_bytes() for i in self.inputs])

    def _get_output_bytes(self) -> bytes:
        """
        Returns the serialized inputs, including input_num
        """
        output_num = len(self.outputs)
        return write_compact_size(output_num) + b''.join([t.to_bytes() for t in self.outputs])

    def _get_witness_bytes(self) -> bytes:
        """
        Returns the serialized witness
        """
        return b''.join([w.to_bytes() for w in self.witness])

    @property
    def is_segwit(self):
        """
        True if the witness_list is populated
        """
        if SEGWIT_KEY not in self._cache:
            self._cache[SEGWIT_KEY] = len(self.witness) > 0
        return self._cache[SEGWIT_KEY]

    @property
    def txid(self):
        """
        Return cached txid if it exists. Otherwise, return new txid
        """
        if TXID_KEY not in self._cache:
            txid_preimage = self._get_txid_preimage()
            self._cache[TXID_KEY] = hash256(txid_preimage)
        return self._cache[TXID_KEY]

    @property
    def wtxid(self):
        """
        Return cached wtxid if it exists. Otherwise, return new txid
        """
        if WTXID_KEY not in self._cache:
            wtxid_preimage = self._get_wtxid_preimage()
            self._cache[WTXID_KEY] = hash256(wtxid_preimage)
        return self._cache[WTXID_KEY]

    @property
    def wu(self):
        """
        Returns size of tx in terms of weight units
        """
        if WU_KEY not in self._cache:
            if self.is_segwit:
                input_length = 0
                output_length = 0
                witness_length = 0
                for i in self.inputs:
                    input_length += i.length
                for o in self.outputs:
                    output_length += o.length
                for w in self.witness:
                    witness_length += w.length

                input_num = len(write_compact_size(len(self.inputs)))
                output_num = len(write_compact_size(len(self.outputs)))

                self._cache[WU_KEY] = 4 * (TX.VERSION + input_num + input_length + output_num + output_length +
                                           TX.LOCKTIME) + (witness_length + TX.MARKERFLAG)
            else:
                self._cache[WU_KEY] = self.length * 4
        return self._cache[WU_KEY]

    @property
    def vbytes(self):
        return round(self.wu / 4, 2)

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # Version
        version = read_little_int(stream, TX.VERSION, "version")

        # Marker/Flag
        marker = stream.read(1)
        if marker == b'\x00':
            flag = stream.read(1)
            if flag != b'\x01':
                raise ValueError("Invalid SegWit flag.")
            segwit = True
        else:
            segwit = False
            stream.seek(-1, SEEK_CUR)  # Rewind the marker byte

        # Read inputs
        num_inputs = read_compact_size(stream)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxInput.from_bytes(stream))

        # Read outputs
        num_outputs = read_compact_size(stream)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOutput.from_bytes(stream))

        # Read witness if segwit
        witness = []
        if segwit:
            for _ in range(num_inputs):
                witness.append(WitnessField.from_bytes(stream))

        # Locktime
        locktime = read_little_int(stream, TX.LOCKTIME, "locktime")

        return cls(inputs, outputs, witness, locktime, version, )

    def to_bytes(self) -> bytes:
        """
        Serialize the tx
        """
        # Get counts ahead of time
        input_num = len(self.inputs)
        output_num = len(self.outputs)

        # Version
        parts = [
            self.version.to_bytes(TX.VERSION, "little"),
        ]

        # Marker/Flag
        if self.is_segwit:
            parts.append(b'\x00\x01')  # Fixed MarkerFlag

        # Inputs/Outputs
        parts.append(self._get_input_bytes())
        parts.append(self._get_output_bytes())

        # Witness
        if self.is_segwit:
            parts.append(self._get_witness_bytes())

        # Locktime
        parts.append(self.locktime.to_bytes(TX.LOCKTIME, "little"))

        return b''.join(parts)

    def to_dict(self) -> dict:
        # Get input and output list
        inputs = [i.to_dict() for i in self.inputs]
        outputs = [o.to_dict() for o in self.outputs]

        # Begin dictionary construction
        tx_dict = {
            "txid": self.txid[::-1].hex(),  # Reverse byte order for display
            "wtxid": self.wtxid[::-1].hex(),  # Reverse byte order for display
            "wu": self.wu,
            "bytes": self.length,
            "vbytes": self.vbytes,
            "version": self.version
        }

        # Segwit check | add marker and flag
        if self.is_segwit:
            tx_dict.update({
                "marker": 0x00,
                "flag": 0x01
            })

        # Add inputs and outputs
        tx_dict.update({
            "input_num": len(self.inputs),
            "inputs": inputs,
            "output_num": len(self.outputs),
            "outputs": outputs
        })

        # Segwit check | add witness
        if self.is_segwit:
            witness = [w.to_dict() for w in self.witness]
            tx_dict.update({
                "witness": witness
            })

        # Add locktime and return
        tx_dict.update({
            "locktime": self.locktime
        })
        return tx_dict


# -- TESTING ---
if __name__ == "__main__":
    # Read in known tx
    known_tx_bytes = bytes.fromhex(
        "01000000000101dd40a8d7f105055e781afa632207f5d3c4b4f4cad9f0fb320d0f0aa8e1ba904b0000000000ffffffff021027000000000000160014858e1f88ff6f383f45a75088e15a095f20fc663f841c0000000000001976a9142241a6c3d4cc3367efaa88b58d24748caef79a7288ac02483045022100d66341c3e6ce846b92bedcf9bc673ab8e47b770c616618eb91009e44816f4c2f0220622b5ebf6afabee3f4255bbcb84609e1185d4b6b1055602f5eed2541e26324620121022ed6c7d33a59cc16d37ad9ba54230696bd5424b8931c2a68ce76b0dbbc222f6500000000")
    known_tx = Transaction.from_bytes(known_tx_bytes)
    print(f"KNOWN TX: {known_tx.to_json()}")
