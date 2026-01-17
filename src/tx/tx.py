"""
The classes for BitClone transactions
"""
import json
from io import SEEK_CUR

from src.core import Serializable, SERIALIZED, get_stream, read_little_int, read_stream, TX
from src.core.byte_stream import read_compact_size
from src.cryptography import hash256
from src.data import write_compact_size

__all__ = ["TxInput", "TxOutput", "WitnessField", "Transaction", "UTXO"]

# --- CACHE KEYS --- #
SEGWIT_KEY = "is_segwit"
TXID_KEY = "txid"
WTXID_KEY = "wtxid"
WU_KEY = "weight_units"
VB_KEY = "virtual_bytes"
COINBASE_KEY = "is_coinbase"


class TxInput(Serializable):
    """
    =============================================================================
    |   name            |   data type   |   format              |   byte size   |
    =============================================================================
    |   txid            |   bytes       |   natural byte order  |   32          |
    |   vout            |   int         |   little-endian       |   4           |
    |   scriptsig_size  |               |   compactSize         |   var         |
    |   scriptsig       |   bytes       |   script bytes        |   var         |
    |   sequence        |   int         |   little-endian       |   4           |
    =============================================================================
    """
    __slots__ = ("txid", "vout", "scriptsig", "sequence")

    def __init__(self, txid: bytes, vout: int | bytes, scriptsig: bytes, sequence: int | bytes):
        self.txid = txid
        self.vout = vout if isinstance(vout, int) else int.from_bytes(vout, "little")
        self.scriptsig = scriptsig
        self.sequence = sequence if isinstance(sequence, int) else int.from_bytes(sequence, "little")

    @property
    def outpoint(self):
        return self.txid + self.vout.to_bytes(TX.VOUT, "little")

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

    def to_dict(self, formatted: bool = True) -> dict:
        ss_len = len(self.scriptsig)
        return {
            "txid": self.txid[::-1].hex() if formatted else self.txid.hex(),
            "vout": self.vout.to_bytes(TX.VOUT, "little").hex() if formatted else self.vout,
            "scriptsig_size": write_compact_size(ss_len).hex() if formatted else ss_len,
            "scriptsig": self.scriptsig.hex(),
            "sequence": self.sequence.to_bytes(TX.SEQUENCE, "little").hex() if formatted else self.sequence
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
        self.amount: int = amount if isinstance(amount, int) else int.from_bytes(amount, "little")
        self.scriptpubkey = scriptpubkey

    @property
    def serial_scriptpubkey(self) -> bytes:
        """
        We return the formatted scriptpubkey_size + scriptpubkey
        """
        return write_compact_size(len(self.scriptpubkey)) + self.scriptpubkey

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
        return self.amount.to_bytes(TX.AMOUNT, "little") + self.serial_scriptpubkey

    def to_dict(self) -> dict:
        return {
            "amount": self.amount.to_bytes(TX.AMOUNT, "little").hex(),
            "amount_int": self.amount,
            "scriptpubkey_size": write_compact_size(len(self.scriptpubkey)).hex(),
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
            witness_items.append(read_stream(stream, item_len, "WitnessField data"))
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
            "stack_items": write_compact_size(len(self.items)).hex()
        }
        for x in range(len(self.items)):
            temp_item = self.items[x]
            witness_dict.update({
                x: {
                    "size": write_compact_size(len(temp_item)).hex(),
                    "data": temp_item.hex()
                }
            })
        witness_dict.update({"serialized": self.to_bytes().hex()})
        return witness_dict


class UTXO:
    """
    Unspent Transaction Output - represents a spendable output
    """
    __slots__ = ("txid", "vout", "amount", "scriptpubkey", "block_height", "is_coinbase")

    def __init__(self, txid: bytes, vout: int, amount: int, scriptpubkey: bytes,
                 block_height: int = None, is_coinbase: bool = False):
        self.txid = txid
        self.vout = vout
        self.amount = amount
        self.scriptpubkey = scriptpubkey
        self.block_height = block_height
        self.is_coinbase = is_coinbase

    @classmethod
    def from_txoutput(cls, txid: bytes, vout: int, txoutput: TxOutput,
                      block_height: int = None, is_coinbase: bool = False):
        """Create UTXO from a TxOutput"""
        return cls(txid, vout, txoutput.amount, txoutput.scriptpubkey,
                   block_height, is_coinbase)

    def outpoint(self) -> bytes:
        """Return txid + vout for referencing. Will be key in the db."""
        return self.txid + self.vout.to_bytes(TX.VOUT, "little")

    def is_mature(self, current_height: int) -> bool:
        """Check if coinbase UTXO is mature (100 blocks)"""
        if not self.is_coinbase or self.block_height is None:
            return True
        return current_height - self.block_height >= 100

    def to_dict(self):
        return {
            "txid": self.txid[::-1].hex(),  # Display txid
            "vout": self.vout,
            "amount": self.amount,
            "scriptpubkey": self.scriptpubkey.hex(),
            "block_height": self.block_height,
            "is_coinbase": False
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other):
        if not isinstance(other, UTXO):
            return False
        return self.outpoint() == other.outpoint()

    def __hash__(self):
        return hash(self.outpoint())

    def __str__(self):
        return f"UTXO({self.txid.hex()[:8]}...:{self.vout}, {self.amount} sats)"


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

    def get_utxo_list(self) -> list[UTXO]:
        """
        We generate UTXOs for the current tx and all its inputs
        """
        utxo_list = []
        for vout in range(0, len(self.outputs)):
            temp_output = self.outputs[vout]
            utxo_list.append(UTXO(
                txid=self.txid,
                vout=vout,
                amount=temp_output.amount,
                scriptpubkey=temp_output.scriptpubkey,
                is_coinbase=False  # Coinbase will have their own Tx type
            ))
        return utxo_list

    @property
    def is_coinbase(self):
        if COINBASE_KEY not in self._cache:
            truth_list = [
                len(self.inputs) == 1,
                self.inputs[0].txid == b'\x00' * 32,
                self.inputs[0].vout == 0xffffffff
            ]
            self._cache[COINBASE_KEY] = all(truth_list)
        return self._cache[COINBASE_KEY]

    @property
    def is_segwit(self):
        """
        True if the witness_list is populated or if any of the inputs don't have a scriptsig (tx to be signed)
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
            "version": self.version.to_bytes(TX.VERSION, "little").hex()
        }

        # Segwit check | add marker and flag
        if self.is_segwit:
            tx_dict.update({
                "marker": 0x00,
                "flag": 0x01
            })

        # Add inputs and outputs
        tx_dict.update({
            "input_num": write_compact_size(len(self.inputs)).hex(),
            "inputs": inputs,
            "output_num": write_compact_size(len(self.outputs)).hex(),
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
            "locktime": self.locktime.to_bytes(TX.LOCKTIME, "little").hex(),
            "is_segwit": self.is_segwit,
            "is_coinbase": self.is_coinbase
        })
        return tx_dict


# -- TESTING ---
if __name__ == "__main__":
    sep = "===" * 50
    space = "\n\n"

    print(" --- TX FORMATTING VALIDATION ---")
    print(sep)

    # TxInput
    test_txid = bytes.fromhex("03bbbdcf71dd288dba0a9936fde33d15d319f74ffe26e670e5871e691bf03929")
    test_vout = 0
    test_scriptsig = bytes.fromhex(
        "47304402203fd3ff375c314f40ef02f2665b61a8219b938b281fb1e75785f01437f7f29254022025cf6fcad3c7bb119a044bde1d4c642a33b19299db9a96d53bb8ec6a2f856a72012102f2d9d8629bffca39151042bd24981ff28f579307a11486c3a6989b18ff090a7f")
    test_sequence = 0xffffffff
    test_txin = TxInput(test_txid, test_vout, test_scriptsig, test_sequence)
    print(f"FORMATTED TEST TXINPUT: {test_txin.to_json()}")
    print(sep)
    print(f"UNFORMATTED TEST TXINPUT: {test_txin.to_json(False)}")
    print(sep)
    print(space)
