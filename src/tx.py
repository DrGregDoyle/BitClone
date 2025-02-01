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
import json
import struct

from src.library.data_handling import check_length, check_hex, write_compact_size, read_compact_size, byte_format
from src.library.hash_functions import hash256


class Serializable:
    """
    A base class that defines the interface for serializing and
    deserializing data to and from Bitcoin's wire format.
    """
    __slots__ = ()

    @classmethod
    def from_bytes(cls, byte_stream):
        raise NotImplementedError(f"{cls.__name__} must implement from_bytes()")

    @classmethod
    def from_hex(cls, hex_string: str):
        hex_string = check_hex(hex_string)
        if len(hex_string) % 2 != 0:
            raise ValueError(f"Invalid hex length for {cls.__name__}")
        return cls.from_bytes(bytes.fromhex(hex_string))

    @property
    def length(self):
        """
        Gives length of the given to_byte serialization
        """
        return len(self.to_bytes())

    def to_bytes(self) -> bytes:
        raise NotImplementedError(f"{self.__class__.__name__} must implement to_bytes()")

    def to_dict(self) -> dict:
        raise NotImplementedError(f"{self.__class__.__name__} must implement to_dict()")

    def to_json(self) -> str:
        """ Convert the object to a JSON string. """
        return json.dumps(self.to_dict(), indent=2)

    def __repr__(self) -> str:
        """ Return a human-readable JSON representation of the object. """
        return self.to_json()


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

    # Constants for fixed-size fields
    TXID_BYTES = 32  # 32-byte transaction ID
    VOUT_BYTES = 4  # 4-byte output index
    SEQ_BYTES = 4  # 4-byte sequence number

    # Struct format for fixed-size fields (txid and vout)
    STRUCT_FORMAT = f"<{TXID_BYTES}sI"  # Little-endian: 32-byte txid and unsigned int vout
    _struct = struct.Struct(STRUCT_FORMAT)  # Precompiled struct for performance

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
        self.vout = vout
        self.script_sig = script_sig
        self.sequence = sequence
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
        fixed_data = stream.read(cls._struct.size)
        check_length(fixed_data, cls.TXID_BYTES + cls.VOUT_BYTES, "outpoint")
        txid, vout = cls._struct.unpack(fixed_data)
        # txid = txid_le[::-1]  # Convert to natural byte order (big-endian)

        # Read script_sig (variable size)
        script_sig_length = read_compact_size(stream)
        script_sig = stream.read(script_sig_length)
        check_length(script_sig, script_sig_length, "script_sig")

        # Read sequence (4 bytes, little-endian)
        sequence_data = stream.read(cls.SEQ_BYTES)
        check_length(sequence_data, cls.SEQ_BYTES, "sequence")
        sequence = int.from_bytes(sequence_data, byteorder="little")

        return cls(txid, vout, script_sig, sequence)

    def to_bytes(self) -> bytes:
        """
        Serialize this input into bytes according to Bitcoin's transaction input format.

        Returns:
            bytes: The serialized transaction input.
        """
        # Pack fixed-size fields
        fixed_part = self._struct.pack(self.txid, self.vout)

        # Pack script_sig (variable size)
        script_sig_part = self.script_sig_size + self.script_sig

        # Pack sequence (4 bytes, little-endian)
        sequence_part = self.sequence.to_bytes(self.SEQ_BYTES, byteorder="little")

        return fixed_part + script_sig_part + sequence_part

    def to_dict(self) -> dict:
        """
        Convert the Input to a dictionary for easy inspection.

        Returns:
            dict: A dictionary representation of the Input.
        """
        return {
            "txid": self.txid.hex(),  # Natural byte order (big-endian)
            "vout": self.vout.to_bytes(self.VOUT_BYTES, "little").hex(),
            "script_sig_size": self.script_sig_size.hex(),
            "script_sig": self.script_sig.hex(),
            "sequence": self.sequence.to_bytes(self.SEQ_BYTES, "little").hex(),
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
    AMOUNT_BYTES = 8

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
        amount = int.from_bytes(amount_data, byteorder="little")

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
        amount_bytes = self.amount.to_bytes(self.AMOUNT_BYTES, byteorder="little")
        script_pubkey_bytes = self.script_pubkey_size + self.script_pubkey
        return amount_bytes + script_pubkey_bytes

    def to_dict(self) -> dict:
        """
        Convert the Output to a dictionary for easy inspection.

        Returns:
            dict: A dictionary representation of the Output.
        """
        return {
            "amount": self.amount.to_bytes(self.AMOUNT_BYTES, byteorder="little").hex(),
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

    @classmethod
    def from_hex(cls, hex_str: str):
        """
        Create an Input instance from a hex string.

        Args:
            hex_str (str): The hex string to deserialize from.

        Returns:
            Input: An instance of the Input class.
        """
        # Check string and use in from_bytes method if valid
        hex_str = check_hex(hex_str)
        return cls.from_bytes(bytes.fromhex(hex_str))

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
    __slots__ = ('version', 'inputs', 'outputs', 'locktime', 'witnesses', 'input_count', 'output_count',
                 '_cached_non_witness_bytes', '_cached_wtxid_bytes')
    VERSION = 2
    VERSION_BYTES = 4
    LOCKTIME_BYTES = 4
    MARKER_BYTES = 1
    FLAG_BYTES = 1
    MARKERFLAG_BYTES = 2
    MARKER = b'\x00'
    FLAG = b'\x01'

    def __init__(self, inputs=None, outputs=None, witnesses=None, locktime: int = 0, version: int = VERSION):
        self.version = version
        self.inputs = inputs or []
        self.outputs = outputs or []
        self.locktime = locktime
        self.witnesses = witnesses or []

        # Get input and output counts
        self.input_count = write_compact_size(len(self.inputs))
        self.output_count = write_compact_size(len(self.outputs))

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
        if not isinstance(byte_stream, bytes):
            raise ValueError("byte_stream must be of type `bytes`.")

        stream = io.BytesIO(byte_stream)

        # Read version (4 bytes, little-endian)
        version_data = stream.read(4)
        check_length(version_data, cls.VERSION_BYTES, "version")
        version = int.from_bytes(version_data, byteorder="little")

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
            # output_data_length = read_compact_size(stream)
            # output_data = stream.read(output_data_length)
            # outputs.append(Output.from_bytes(output_data))

        # Read witnesses if SegWit
        witnesses = []
        if is_segwit:
            for _ in range(num_inputs):
                witnesses.append(Witness.from_bytes(stream))

        # Read locktime (4 bytes, little-endian)
        locktime_data = stream.read(4)
        check_length(locktime_data, cls.LOCKTIME_BYTES, "locktime")
        locktime = int.from_bytes(locktime_data, byteorder="little")

        return cls(inputs, outputs, witnesses, locktime, version)

    @classmethod
    def from_hex(cls, hex_string: str):
        # Format string and remove leading 0x if it exists
        if hex_string.startswith("0x"):
            hex_string = hex_string[2:]
        hex_string = hex_string.lower()

        # Check the string
        if not all(c in "0123456789abcedf" for c in hex_string):
            raise ValueError("String contains non hexadecimal characters")

        # Turn hex to bytes and return from_bytes
        return cls.from_bytes(bytes.fromhex(hex_string))

    @property
    def is_segwit(self) -> bool:
        return len(self.witnesses) > 0

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
        version_bytes = self.version.to_bytes(self.VERSION_BYTES, "little")
        marker_flag_bytes = self.MARKER + self.FLAG if self.is_segwit else b''

        # Inputs, outputs and witness
        inputs_bytes = self.input_count + b''.join(i.to_bytes() for i in self.inputs)
        outputs_bytes = self.output_count + b''.join(o.to_bytes() for o in self.outputs)
        witnesses_bytes = b''.join(w.to_bytes() for w in self.witnesses) if self.is_segwit else b''

        # Locktime and return
        locktime_bytes = self.locktime.to_bytes(self.LOCKTIME_BYTES, "little")
        return version_bytes + marker_flag_bytes + inputs_bytes + outputs_bytes + witnesses_bytes + locktime_bytes

    def to_dict(self) -> dict:
        """
        Convert the Transaction to a dictionary for easy inspection.

        Returns:
            dict: A dictionary representation of the Transaction.
        """
        # 1. Add "version" as a 4-byte little-endian hex string
        tx_dict = {
            "version": self.version.to_bytes(self.VERSION_BYTES, "little").hex()
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
        tx_dict["locktime"] = self.locktime.to_bytes(self.LOCKTIME_BYTES, "little").hex()
        return tx_dict

    def txid(self) -> str:
        """
        Compute the transaction ID (txid) as the double SHA-256 of the transaction
        without witness data.
        """
        if self._cached_non_witness_bytes is None:
            self._cached_non_witness_bytes = self._serialize_non_witness()
        txid_hash = hash256(self._cached_non_witness_bytes)
        return txid_hash[::-1].hex()

    def wtxid(self) -> str:
        """
        Compute the witness transaction ID (wtxid) as the double SHA-256
        of the full serialized transaction (including witness data).
        """
        if self._cached_wtxid_bytes is None:
            self._cached_wtxid_bytes = self.to_bytes()
        wtxid_hash = hash256(self._cached_wtxid_bytes)
        return wtxid_hash[::-1].hex()

    def _serialize_non_witness(self) -> bytes:
        """
        Serialize the transaction without witness data (needed for txid calculation).

        Returns:
            bytes: The serialized transaction in Bitcoin's standard format, excluding witness data.
        """
        version_bytes = self.version.to_bytes(self.VERSION_BYTES, byteorder="little")
        inputs_bytes = self.input_count + b''.join(i.to_bytes() for i in self.inputs)
        outputs_bytes = write_compact_size(len(self.outputs)) + b''.join(o.to_bytes() for o in self.outputs)
        locktime_bytes = self.locktime.to_bytes(self.LOCKTIME_BYTES, byteorder="little")

        return version_bytes + inputs_bytes + outputs_bytes + locktime_bytes


# -- TESTING
if __name__ == "__main__":
    test_tx_hex = "01000000000101438afdb24e414d54cc4a17a95f3d40be90d23dfeeb07a48e9e782178efddd8890100000000fdffffff020db9a60000000000160014b549d227c9edd758288112fe3573c1f85240166880a81201000000001976a914ae28f233464e6da03c052155119a413d13f3380188ac024730440220200254b765f25126334b8de16ee4badf57315c047243942340c16cffd9b11196022074a9476633f093f229456ad904a9d97e26c271fc4f01d0501dec008e4aae71c2012102c37a3c5b21a5991d3d7b1e203be195be07104a1a19e5c2ed82329a56b431213000000000"
    test_tx = Transaction.from_hex(test_tx_hex)
    print(test_tx)
    print(f"BYTES: {test_tx.length}")
    print(f"WEIGHT: {test_tx.wu}")
    print(f"VBYTES: {test_tx.vbytes}")
    print(f"TXID: {test_tx.txid()}")
    print(f"WTXID: {test_tx.wtxid()}")
