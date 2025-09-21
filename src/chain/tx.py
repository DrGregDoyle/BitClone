"""
The classes for BitClone transactions
"""
from io import SEEK_CUR

from src.core import Serializable, SERIALIZED, get_stream, read_little_int, read_stream, TX
from src.data import read_compact_size, write_compact_size

__all__ = ["TxInput", "TxOutput", "WitnessField"]

# --- CACHE KEYS --- #
SEGWIT_KEY = "is_segwit"


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
    __slots__ = ("witness_items",)

    def __init__(self, witness_items: list | bytes):
        self.witness_items = witness_items if isinstance(witness_items, list) else [witness_items]

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
        parts = [write_compact_size(len(self.witness_items))]
        for item in self.witness_items:
            parts.append(write_compact_size(len(item)))
            parts.append(item)
        return b''.join(parts)

    def to_dict(self) -> dict:
        witness_dict = {
            "stack_items": len(self.witness_items)
        }
        for x in range(len(self.witness_items)):
            temp_item = self.witness_items[x]
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

    def _invalidate_cache(self):
        """
        Remove all cache values
        """
        self._cache = {}

    @property
    def is_segwit(self):
        """
        True if the witness_list is populated
        """
        if SEGWIT_KEY not in self._cache:
            self._cache[SEGWIT_KEY] = len(self.witness) > 0
        return self._cache[SEGWIT_KEY]

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


# -- TESTING ---
if __name__ == "__main__":
    pass
    # test_dict = {
    #     "is_segwit": True,
    #     "is_full": False,
    #     "is_heavy": None
    # }
    # var1 = test_dict.get("is_segwit")
    # var2 = test_dict.get("is_light")
    # print(f"VAR 1: CORRECT KEY: {var1}")
    # print(f"VAR 2: INCORRECT KEY: {var2}")
    # if "is_light" not in test_dict:
    #     print(f"KEYS: {test_dict.keys()}")
    # if True not in test_dict:
    #     print(f"VALS: {test_dict.items()}")
    # if "is_segwit" not in test_dict:
    #     print(f"FULL: {json.dumps(test_dict, indent=2)}")
