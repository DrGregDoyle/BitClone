"""
Classes for Bitcoin tx's

struct.unpack shortcuts:
B: unsigned char (1 byte)
<H: uint16 (little-endian)
>H: uint16 (big-endian)
<I: uint32 (little-endian)
>I: uint32 (big-endian)
<Q: uint64 (little-endian)
>Q: uint64 (big-endian)
"""
import io
from dataclasses import dataclass

from src.crypto.hash_functions import hash256
from src.data import Serializable, write_compact_size, read_compact_size, byte_format, from_little_bytes, \
    to_little_bytes, check_length


class Input(Serializable):
    """
    Represents a Bitcoin transaction input.

    Attributes:
        txid (bytes): The 32-byte transaction hash in natural byte order (big-endian).
        vout (int): The index of the output in the previous transaction (4 bytes).
        script_sig (bytes): The scriptSig, variable in length.
        sequence (int): The sequence number (4 bytes).
    """
    __slots__ = ('txid', 'vout', 'script_sig_size', 'script_sig', 'sequence')

    def __init__(self, txid: bytes, vout: int, script_sig: bytes, sequence: int):
        """
        Initialize a transaction input.

        Args:
            txid (bytes): The transaction ID in natural byte order (big-endian).
            vout (int): The output index.
            script_sig (bytes): The scriptSig.
            sequence (int): The sequence number.

        """
        # Pad w 0's if len(txid) < 32
        self.txid = byte_format(txid, self.TXID_BYTES)  # Store in natural byte order (big-endian)
        self.vout = vout  # integer
        self.script_sig = script_sig  # bytes object
        self.sequence = sequence  # integer
        self.script_sig_size = write_compact_size(len(self.script_sig))

    @classmethod
    def from_bytes(cls, byte_stream: bytes | io.BytesIO) -> 'Input':
        """
        Deserialize a transaction input from bytes.

        Args:
            byte_stream (bytes): The byte stream to deserialize from.

        Returns:
            Input: An instance of the Input class.

        Raises:
            ValueError: If the byte_stream is invalid or incomplete.
        """
        if not isinstance(byte_stream, (bytes, io.BytesIO)):
            raise ValueError("byte_stream must be of type `bytes`.")

        stream = io.BytesIO(byte_stream) if isinstance(byte_stream, bytes) else byte_stream

        # Read fixed-size fields (txid and vout)
        txid = stream.read(cls.TXID_BYTES)
        check_length(txid, cls.TXID_BYTES, "txid")
        vout = stream.read(cls.VOUT_BYTES)
        check_length(vout, cls.VOUT_BYTES, "vout")
        vout_int = int.from_bytes(vout, "little")

        # Read script_sig (variable size)
        script_sig_length = read_compact_size(stream)
        script_sig = stream.read(script_sig_length)
        check_length(script_sig, script_sig_length, "script_sig")

        # Read sequence (4 bytes, little-endian)
        sequence_data = stream.read(cls.SEQ_BYTES)
        check_length(sequence_data, cls.SEQ_BYTES, "sequence")
        sequence = from_little_bytes(sequence_data)

        return cls(txid, vout_int, script_sig, sequence)

    def to_bytes(self) -> bytes:
        """
        Serializes the transaction input.
        """
        return (
                self.txid + to_little_bytes(self.vout, 4) +
                self.script_sig_size + self.script_sig +
                to_little_bytes(self.sequence, 4)
        )

    def to_dict(self) -> dict:
        """
        Convert the Input to a dictionary for easy inspection.

        Returns:
            dict: A dictionary representation of the Input.
        """
        return {
            "txid": self.txid.hex(),  # Natural byte order (big-endian)
            "vout": to_little_bytes(self.vout, self.VOUT_BYTES).hex(),
            "script_sig_size": self.script_sig_size.hex(),
            "script_sig": self.script_sig.hex(),
            "sequence": to_little_bytes(self.sequence, self.SEQ_BYTES).hex()

        }


class Output(Serializable):
    """
    Represents a Bitcoin transaction output.

    Attributes:
        amount (int): The amount in satoshis (8 bytes).
        script_pubkey (bytes): The scriptPubKey that locks this output.
        script_pubkey_size (bytes): The CompactZie encoding of the length of the script_pubkey
    """
    __slots__ = ('amount', 'script_pubkey', 'script_pubkey_size')

    def __init__(self, amount: int, script_pubkey: bytes):
        self.amount = amount
        self.script_pubkey = script_pubkey
        self.script_pubkey_size = write_compact_size(len(self.script_pubkey))

    @classmethod
    def from_bytes(cls, byte_stream):
        """
        Deserialize a transaction output from the given byte_stream.
        Example pseudo-steps:
          1. Read 8-byte value
          2. Read scriptPubKey length (CompactSize), then scriptPubKey
        """
        if not isinstance(byte_stream, (bytes, io.BytesIO)):
            raise ValueError("byte_stream must be of type `bytes`.")

        stream = io.BytesIO(byte_stream) if isinstance(byte_stream, bytes) else byte_stream

        # Read fixed size fields (amount)
        amount_data = stream.read(cls.AMOUNT_BYTES)
        check_length(amount_data, cls.AMOUNT_BYTES, "amount")
        amount = from_little_bytes(amount_data)

        # Read script_pubkey (variable size)
        script_pubkey_length = read_compact_size(stream)
        script_pubkey = stream.read(script_pubkey_length)
        check_length(script_pubkey, script_pubkey_length, "script_pubkey")

        return cls(amount, script_pubkey)

    def to_bytes(self) -> bytes:
        """
        Serialize this output into bytes according to Bitcoin's transaction output format.
        Example pseudo-steps:
          1. value (8 bytes)
          2. CompactSize for scriptPubKey length, then script_pubkey
        """
        amount_bytes = to_little_bytes(self.amount, self.AMOUNT_BYTES)
        script_pubkey_bytes = self.script_pubkey_size + self.script_pubkey
        return amount_bytes + script_pubkey_bytes

    def to_dict(self) -> dict:
        """
        Convert the Output to a dictionary for easy inspection.

        Returns:
            dict: A dictionary representation of the Output.
        """
        return {
            "amount": to_little_bytes(self.amount, self.AMOUNT_BYTES).hex(),
            "script_pubkey_size": self.script_pubkey_size.hex(),
            "script_pubkey": self.script_pubkey.hex(),
        }


class WitnessItem(Serializable):
    """
    Represents a Bitcoin witness item. Contains bytes data and the associated length in compact size encoding
    """
    __slots__ = ('item', 'size')

    def __init__(self, item: bytes):
        self.item = item
        self.size = write_compact_size(len(self.item))

    @classmethod
    def from_bytes(cls, byte_stream):
        if not isinstance(byte_stream, (bytes, io.BytesIO)):
            raise ValueError("byte_stream must be of type `bytes`.")

        stream = io.BytesIO(byte_stream) if isinstance(byte_stream, bytes) else byte_stream

        # Read compact size and item
        item_length = read_compact_size(stream)
        item = stream.read(item_length)
        check_length(item, item_length, "witness item")

        return cls(item)

    def to_bytes(self) -> bytes:
        return self.size + self.item

    def to_dict(self) -> dict:
        return {
            "size": self.size.hex(),
            "item": self.item.hex()
        }


class Witness(Serializable):
    """
    Represents a Bitcoin witness field (used in SegWit transactions).

    Attributes:
        items (list[bytes]): The stack items in the witness.
    """
    __slots__ = ('items', 'stackitems')

    def __init__(self, items: list = None):
        if items is None:
            items = []
        self.items = items
        self.stackitems = write_compact_size(len(self.items))

    @classmethod
    def from_bytes(cls, byte_stream):
        """
        Deserialize witness data from the given byte_stream.
        Example pseudo-steps:
          1. Read a CompactSize indicating the number of stack items
          2. For each item, read a CompactSize length then read that many bytes
        """
        # Check type
        if not isinstance(byte_stream, (bytes, io.BytesIO)):
            raise ValueError(f"Expected byte data stream, received {type(byte_stream)}")

        stream = io.BytesIO(byte_stream) if isinstance(byte_stream, bytes) else byte_stream

        num_items = read_compact_size(stream)
        items = []
        # Loop needed to properly read stream | Do NOT use list comprehension
        for _ in range(num_items):
            items.append(WitnessItem.from_bytes(stream))

        return cls(items)

    def to_bytes(self) -> bytes:
        """
        Serialize the witness data into bytes.
        Example pseudo-steps:
          1. Write a CompactSize for the number of items
          2. For each item, write the length as a CompactSize, then the item bytes
        """

        items_bytes = b""
        for item in self.items:
            items_bytes += item.to_bytes()
        return self.stackitems + items_bytes

    def to_dict(self) -> dict:
        """
        Convert the Witness to a dictionary for easy inspection.

        Returns:
            dict: A dictionary representation of the Witness.
        """
        witness_dict = {
            "stackitems": self.stackitems.hex()
        }
        for x in range(len(self.items)):
            witness_dict.update({
                x: self.items[x].to_dict()
            })
        return witness_dict


@dataclass
class UTXO:
    txid: bytes  # Transaction ID that created this UTXO
    vout: int  # Output index in the transaction
    amount: int  # Amount in satoshis
    script_pubkey: bytes  # Script that locks this output
    spent: bool = False  # Indicates whether the UTXO has been spent (default is False)

    @classmethod
    def from_tuple(cls, data: tuple):
        """
        Creates UTXO from db entry
        """
        txid, vout, amount, script_pubkey, spent = data
        return cls(txid, vout, amount, script_pubkey, bool(spent))

    def to_dict(self) -> dict:
        """Converts the UTXO to a dictionary."""
        return {
            "txid": self.txid.hex(),
            "vout": self.vout,
            "amount": self.amount,
            "script_pubkey": self.script_pubkey.hex(),
            "spent": self.spent
        }


class Transaction(Serializable):
    """
    Represents a Bitcoin transaction.

    Attributes:
        version (int): The transaction version (4 bytes).
        inputs (list[Input]): A list of transaction inputs.
        outputs (list[Output]): A list of transaction outputs.
        locktime (int): The locktime (4 bytes).
        witnesses (list[Witness]): The witness data (if present, for SegWit transactions).
        input_count (bytes): CompactSize-encoded number of inputs.
        output_count (bytes): CompactSize-encoded number of outputs.
    """
    __slots__ = ('version', 'inputs', 'outputs', 'locktime', 'witnesses', 'input_count', 'output_count', 'is_segwit',
                 '_cached_non_witness_bytes', '_cached_wtxid_bytes', 'sighash')

    def __init__(self, inputs=None, outputs=None, witnesses=None, locktime: int = 0, version: int = None):
        self.version = version or self.VERSION
        self.inputs = inputs or []
        self.outputs = outputs or []
        self.locktime = locktime
        self.witnesses = witnesses if witnesses else []

        # Get input and output counts
        self.input_count = write_compact_size(len(self.inputs))
        self.output_count = write_compact_size(len(self.outputs))

        # Get segwit bool
        self.is_segwit = len(self.witnesses) > 0

        self._cached_non_witness_bytes = None  # Cache for txid computation
        self._cached_wtxid_bytes = None  # Cache for wtxid computation

    @classmethod
    def from_bytes(cls, byte_stream):
        """
        Deserialize a transaction from the given byte_stream.
        This includes reading version, inputs, outputs, and locktime.
        If the transaction is a SegWit transaction, handle witness fields accordingly.
        Example pseudo-steps:
          1. Read 4-byte version
          2. Check marker + flag if it's segwit
          3. Read inputs (with CompactSize count)
          4. Read outputs (with CompactSize count)
          5. If segwit, read witness data for each input
          6. Read 4-byte locktime
        """
        if not isinstance(byte_stream, (bytes, io.BytesIO)):
            raise ValueError(f"Expected byte data stream, received {type(byte_stream)}")

        stream = io.BytesIO(byte_stream) if isinstance(byte_stream, bytes) else byte_stream

        # Read version (4 bytes, little-endian)
        version_data = stream.read(4)
        check_length(version_data, cls.VERSION_BYTES, "version")
        version = from_little_bytes(version_data)

        # Check for SegWit marker and flag
        marker = stream.read(1)
        if marker == b'\x00':
            flag = stream.read(1)
            if flag != b'\x01':
                raise ValueError("Invalid SegWit flag.")
            is_segwit = True
        else:
            is_segwit = False
            stream.seek(-1, io.SEEK_CUR)  # Rewind the marker byte

        # Read inputs
        num_inputs = read_compact_size(stream)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(Input.from_bytes(stream))

        # Read outputs
        num_outputs = read_compact_size(stream)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(Output.from_bytes(stream))

        # Read witnesses if SegWit
        witnesses = []
        if is_segwit:
            for _ in range(num_inputs):
                witnesses.append(Witness.from_bytes(stream))

        # Read locktime (4 bytes, little-endian)
        print(f"STREAM BEFORE READING LOCKTIME DATA: {stream}")
        locktime_data = stream.read(4)
        check_length(locktime_data, cls.LOCKTIME_BYTES, "locktime")
        locktime = from_little_bytes(locktime_data)
        print(f"FROM BYTES: LOCKTIME BYTES: {locktime}")

        return cls(inputs, outputs, witnesses, locktime, version)

    @property
    def wu(self):
        """
        Returns weight measurement of the tx data
        """
        if self.is_segwit:
            input_length = 0
            output_length = 0
            witness_length = 0
            for i in self.inputs:
                input_length += i.length
            for o in self.outputs:
                output_length += o.length
            for w in self.witnesses:
                witness_length += w.length

            return (self.VERSION_BYTES + input_length + output_length + self.LOCKTIME_BYTES) * 4 + (
                    self.MARKERFLAG_BYTES + witness_length)
        else:
            return self.length * 4

    @property
    def vbytes(self):
        return round(self.wu / 4, 2)

    def get_utxos(self):
        """
        Return a list of UTXOs associated with the transaction
        """
        utxo_list = []
        for p in self.outputs:
            output_index = self.outputs.index(p)
            utxo_list.append(UTXO(self.txid(), output_index, p.amount, p.script_pubkey))
        return utxo_list

    def to_bytes(self) -> bytes:
        """
        Serialize this transaction into bytes according to Bitcoin's transaction format.
        This includes version, inputs, outputs, (optionally witness), and locktime.
        Example pseudo-steps:
          1. version (4 bytes)
          2. If witnesses exist, write marker and flag
          3. CompactSize for input count, then each input
          4. CompactSize for output count, then each output
          5. If segwit, serialize witness data
          6. locktime (4 bytes)
        """
        # Version and Marker/Flag (if segwit)
        version_bytes = to_little_bytes(self.version, self.VERSION_BYTES)
        marker_flag_bytes = b'\x00\x01' if self.is_segwit else b''  # Marker + Flag = 0001

        # Inputs, outputs and witness
        inputs_bytes = self.input_count + b''.join(i.to_bytes() for i in self.inputs) if self.inputs else \
            self.input_count + b''
        outputs_bytes = self.output_count + b''.join(o.to_bytes() for o in self.outputs) if self.outputs else b''
        witnesses_bytes = b''.join(w.to_bytes() for w in self.witnesses) if self.is_segwit else self.output_count + b''

        # Locktime and return
        locktime_bytes = to_little_bytes(self.locktime, self.LOCKTIME_BYTES)
        print(f"TO BYTES LOCKTIME BYTES: {locktime_bytes.hex()}")
        return version_bytes + marker_flag_bytes + inputs_bytes + outputs_bytes + witnesses_bytes + locktime_bytes

    def to_dict(self) -> dict:
        """
        Convert the Transaction to a dictionary for easy inspection.

        Returns:
            dict: A dictionary representation of the Transaction.
        """
        # 1. Start with tx_id and version
        tx_dict = {
            "tx_id": self.txid()[::-1].hex(),  # Reverse bytes for display
            "version": to_little_bytes(self.version, self.VERSION_BYTES).hex()
        }

        # 2. If SegWit, add "marker" and "flag"
        if self.is_segwit:
            tx_dict["marker"] = "00"
            tx_dict["flag"] = "01"

        # 3. Add inputs and outputs
        tx_dict["inputcount"] = self.input_count.hex()
        tx_dict["inputs"] = [i.to_dict() for i in self.inputs]
        tx_dict["outputcount"] = self.output_count.hex()
        tx_dict["outputs"] = [i.to_dict() for i in self.outputs]

        # 4. If SegWit, add witness
        if self.is_segwit:
            tx_dict["witnesses"] = [w.to_dict() for w in self.witnesses]

        # 5. Add locktime and return
        tx_dict["locktime"] = to_little_bytes(self.locktime, self.LOCKTIME_BYTES).hex()
        return tx_dict

    def txid(self) -> bytes:
        """
        Compute the transaction ID (txid) as the double SHA-256 of the transaction
        without witness data.
        """
        if self._cached_non_witness_bytes is None:
            self._cached_non_witness_bytes = self._serialize_non_witness()
        return hash256(self._cached_non_witness_bytes)

    def wtxid(self) -> bytes:
        """
        Compute the witness transaction ID (wtxid) as the double SHA-256
        of the full serialized transaction (including witness data).
        """
        if self._cached_wtxid_bytes is None:
            self._cached_wtxid_bytes = self.to_bytes()
        return hash256(self._cached_wtxid_bytes)

    def _serialize_non_witness(self) -> bytes:
        """
        Serialize the transaction without witness data (needed for txid calculation).

        Returns:
            bytes: The serialized transaction in Bitcoin's standard format, excluding witness data.
        """
        version_bytes = to_little_bytes(self.version, self.VERSION_BYTES)
        inputs_bytes = self.input_count + b''.join(i.to_bytes() for i in self.inputs) if self.inputs else \
            self.input_count + b''
        outputs_bytes = self.output_count + b''.join(o.to_bytes() for o in self.outputs) if self.outputs else \
            self.output_count + b''
        locktime_bytes = to_little_bytes(self.locktime, self.LOCKTIME_BYTES)
        return version_bytes + inputs_bytes + outputs_bytes + locktime_bytes
