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
from io import SEEK_CUR, BytesIO

from src.backup.crypto.hash_functions import hash256
from src.backup.data import Serializable, byte_format, to_little_bytes, get_stream, \
    read_stream, read_little_int, TxFmt
from src.backup.data import UTXO
from src.backup.data.varint import write_compact_size, read_compact_size


# alias
# BFT = BitcoinFormats.Tx
# BFP = BitcoinFormats.Protocol


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
        self.txid = byte_format(txid, TxFmt.TXID_LEN)  # Store in natural byte order (big-endian)
        self.vout = vout  # integer
        self.script_sig = script_sig  # bytes object
        self.sequence = sequence  # integer
        self.script_sig_size = write_compact_size(len(self.script_sig))

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO) -> 'Input':
        """
        Deserialize a transaction input from bytes.

        Args:
            byte_stream (bytes): The byte stream to deserialize from.

        Returns:
            Input: An instance of the Input class.

        Raises:
            ValueError: If the byte_stream is invalid or incomplete.
        """
        stream = get_stream(byte_stream)  # Get byte stream

        # Read fixed-size fields (txid and vout)
        txid = read_stream(stream, TxFmt.TXID_LEN, "txid")
        vout = read_little_int(stream, TxFmt.VOUT_LEN, "vout")

        # Read script_sig (variable size)
        script_sig_length = read_compact_size(stream)
        script_sig = read_stream(stream, script_sig_length, "script_sig")

        # Read sequence (4 bytes, little-endian)
        sequence = read_little_int(stream, TxFmt.SEQUENCE_LEN, "sequence")

        return cls(txid, vout, script_sig, sequence)

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
            "vout": self.vout.to_bytes(TxFmt.VOUT_LEN, "little").hex(),
            "script_sig_size": self.script_sig_size.hex(),
            "script_sig": self.script_sig.hex(),
            "sequence": self.sequence.to_bytes(TxFmt.SEQUENCE_LEN, "little").hex()
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
        stream = get_stream(byte_stream)

        # Read fixed size fields (amount)
        amount = read_little_int(stream, TxFmt.AMOUNT_LEN, "amount")

        # Read script_pubkey (variable size)
        script_pubkey_length = read_compact_size(stream)
        script_pubkey = read_stream(stream, script_pubkey_length, "script_pubkey")

        return cls(amount, script_pubkey)

    def to_bytes(self) -> bytes:
        """
        Serialize this output into bytes according to Bitcoin's transaction output format.
        Example pseudo-steps:
          1. value (8 bytes)
          2. CompactSize for scriptPubKey length, then script_pubkey
        """
        amount_bytes = to_little_bytes(self.amount, TxFmt.AMOUNT_LEN)
        script_pubkey_bytes = self.script_pubkey_size + self.script_pubkey
        return amount_bytes + script_pubkey_bytes

    def to_dict(self) -> dict:
        """
        Convert the Output to a dictionary for easy inspection.

        Returns:
            dict: A dictionary representation of the Output.
        """
        return {
            "amount": to_little_bytes(self.amount, TxFmt.AMOUNT_LEN).hex(),
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
        self.size = len(self.item)

    @classmethod
    def from_bytes(cls, byte_stream):
        stream = get_stream(byte_stream)

        # Read compact size and item
        item_length = read_compact_size(stream)
        item = read_stream(stream, item_length, "witness_item")

        return cls(item)

    def to_bytes(self) -> bytes:
        return write_compact_size(self.size) + self.item

    def to_dict(self) -> dict:
        return {
            "size": write_compact_size(self.size).hex(),
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
        self.stackitems = len(self.items)  # int value as instance variable

    @classmethod
    def from_bytes(cls, byte_stream):
        """
        Deserialize witness data from the given byte_stream.
        Example pseudo-steps:
          1. Read a CompactSize indicating the number of stack items
          2. For each item, read a CompactSize length then read that many bytes
        """
        # Check type
        stream = get_stream(byte_stream)

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
        return write_compact_size(self.stackitems) + items_bytes

    def to_dict(self) -> dict:
        """
        Convert the Witness to a dictionary for easy inspection.

        Returns:
            dict: A dictionary representation of the Witness.
        """
        witness_dict = {
            "stackitems": write_compact_size(self.stackitems).hex()
        }
        for x in range(len(self.items)):
            witness_dict.update({
                x: self.items[x].to_dict()
            })
        return witness_dict


class Transaction(Serializable):
    """
    Represents a Bitcoin transaction.

    This class can be used to construct a finished transaction or, more likely, create a Transaction for signing.
    This means we will enable the "segwit" boolean, which specifies whether a Transaction contains

    """
    __slots__ = ('version', 'inputs', 'outputs', 'locktime', 'witnesses', 'input_count', 'output_count', 'segwit',
                 '_cached_non_witness_bytes', '_cached_wtxid_bytes', 'sighash', 'coinbase')
    MINIMUM_VERSION = 2

    def __init__(self, inputs: list[Input] = None, outputs: list[Output] = None, witnesses: list[Witness] = None,
                 locktime: int = 0, version: int = None, segwit: bool = True):
        self.version = version or self.MINIMUM_VERSION
        self.inputs = inputs or []
        self.outputs = outputs or []
        self.locktime = locktime
        self.witnesses = witnesses if witnesses else []

        # Get input and output counts
        # TODO: Modify input and output count to be integers rather than compact sizes
        self.input_count = write_compact_size(len(self.inputs))
        self.output_count = write_compact_size(len(self.outputs))

        # Get segwit bool
        self.segwit = segwit

        # Check or fill witnesses
        if self.segwit:
            # Check witnesses
            if self.witnesses:
                if len(self.witnesses) != len(self.inputs):
                    raise ValueError("Given number of witness objects doesn't agree with number of inputs")
            else:
                # No witnesses case for segwit tx
                self.witnesses = [Witness() for _ in range(len(self.inputs))]

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
        stream = get_stream(byte_stream)

        # Read version (4 bytes, little-endian)
        version = read_little_int(stream, TxFmt.VERSION_LEN, "version")

        # Check for SegWit marker and flag
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
            inputs.append(Input.from_bytes(stream))

        # Read outputs
        num_outputs = read_compact_size(stream)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(Output.from_bytes(stream))

        # Read witnesses if SegWit
        witnesses = []
        if segwit:
            for _ in range(num_inputs):
                witnesses.append(Witness.from_bytes(stream))

        # Read locktime (4 bytes, little-endian)
        locktime = read_little_int(stream, TxFmt.LOCKTIME_LEN, "locktime")

        return cls(inputs, outputs, witnesses, locktime, version, segwit)

    @property
    def wu(self):
        """
        Returns weight measurement of the tx data
        """
        if self.segwit:
            input_length = 0
            output_length = 0
            witness_length = 0
            for i in self.inputs:
                input_length += i.length
            for o in self.outputs:
                output_length += o.length
            for w in self.witnesses:
                witness_length += w.length

            return (TxFmt.VERSION_LEN + input_length + output_length + TxFmt.LOCKTIME_LEN) * 4 + (
                    TxFmt.MARKERFLAG + witness_length)
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
        txid = self.txid()
        for p in self.outputs:
            output_index = self.outputs.index(p)
            utxo_list.append(UTXO(txid, output_index, p.amount, p.script_pubkey))
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
        version_bytes = to_little_bytes(self.version, TxFmt.VERSION_LEN)
        marker_flag_bytes = b'\x00\x01' if self.segwit else b''  # Marker + Flag = 0001

        # Inputs, outputs and witness
        inputs_bytes = self.input_count + b''.join(i.to_bytes() for i in self.inputs) if self.inputs else \
            self.input_count + b''
        outputs_bytes = self.output_count + b''.join(o.to_bytes() for o in self.outputs) if self.outputs else \
            self.output_count + b''
        witnesses_bytes = b''.join(w.to_bytes() for w in self.witnesses) if self.segwit else b''

        # Locktime and return
        locktime_bytes = to_little_bytes(self.locktime, TxFmt.LOCKTIME_LEN)
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
            "version": to_little_bytes(self.version, TxFmt.VERSION_LEN).hex()
        }

        # 2. If SegWit, add "marker" and "flag"
        if self.segwit:
            tx_dict["marker"] = "00"
            tx_dict["flag"] = "01"

        # 3. Add inputs and outputs
        tx_dict["inputcount"] = self.input_count.hex()
        tx_dict["inputs"] = {f"input_{x}": self.inputs[x].to_dict() for x in range(len(self.inputs))}
        # tx_dict["inputs"] = [i.to_dict() for i in self.inputs]
        tx_dict["outputcount"] = self.output_count.hex()
        # tx_dict["outputs"] = [i.to_dict() for i in self.outputs]

        # 4. If SegWit, add witness
        if self.segwit:
            tx_dict["witnesses"] = {f"witness_{x}": self.witnesses[x].to_dict() for x in range(len(self.witnesses))}
            # tx_dict["witnesses"] = [w.to_dict() for w in self.witnesses]

        # 5. Add locktime and return
        tx_dict["locktime"] = to_little_bytes(self.locktime, TxFmt.LOCKTIME_LEN).hex()
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
        version_bytes = to_little_bytes(self.version, TxFmt.VERSION_LEN)
        inputs_bytes = self.input_count + b''.join(i.to_bytes() for i in self.inputs) if self.inputs else \
            self.input_count + b''
        outputs_bytes = self.output_count + b''.join(o.to_bytes() for o in self.outputs) if self.outputs else \
            self.output_count + b''
        locktime_bytes = to_little_bytes(self.locktime, TxFmt.LOCKTIME_LEN)
        return version_bytes + inputs_bytes + outputs_bytes + locktime_bytes


# --- COMPACT BLOCKS
class PrefilledTransaction(Serializable):
    """
    -------------------------------------------------------------
    |   Name    |   Data type   |   byte format |   byte size   |
    -------------------------------------------------------------
    |   Index   |   int         |   CompactSize |   varInt      |
    |   Tx      |   Transaction |   tx.to_bytes |   var         |
    -------------------------------------------------------------
    """

    def __init__(self, index: int, tx: Transaction):
        self.index = index
        self.tx = tx

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        stream = get_stream(byte_stream)

        # index
        index = read_compact_size(stream, "prefilled_tx_index")

        # tx
        tx = Transaction.from_bytes(stream)

        return cls(index, tx)

    def to_bytes(self) -> bytes:
        return write_compact_size(self.index) + self.tx.to_bytes()

    def to_dict(self):
        prefilled_tx_dict = {
            "index": self.index,
            "tx": self.tx.to_dict()
        }
        return prefilled_tx_dict


# --- COINBASE
class Coinbase(Transaction):
    def __init__(self, script_sig: bytes = None, outputs: list[Output] = None, locktime: int = 0, version: int = None,
                 segwit: bool = True):
        inputs = [make_coinbase_input(script_sig)]
        witnesses = [make_coinbase_witness()] if segwit else []

        super().__init__(
            inputs=inputs,
            outputs=outputs,
            witnesses=witnesses,
            locktime=locktime,
            version=version,
            segwit=segwit
        )
        self.coinbase = True


def make_coinbase_input(script_sig: bytes, sequence: int = 0xffffffff) -> Input:
    txid = b'\x00' * 32
    vout = 0xffffffff
    return Input(txid, vout, script_sig, sequence)


def make_coinbase_witness():
    return Witness([WitnessItem(b'\x00' * 32)])


if __name__ == "__main__":
    w1 = Witness()
    print(f"EMPTY WITNESS: {w1.to_json()}")
    print(f"EMPTY WITNESS BYTES: {w1.to_bytes().hex()}")
    print(f"CONSTRUCTED WITNESS: {Witness.from_bytes(w1.to_bytes()).to_json()}")

    test_tx = Transaction.from_bytes(bytes.fromhex(
        "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804233fa04e028b12ffffffff0130490b2a010000004341047eda6bd04fb27cab6e7c28c99b94977f073e912f25d1ff7165d9c95cd9bbe6da7e7ad7f2acb09e0ced91705f7616af53bee51a238b7dc527f2be0aa60469d140ac00000000"))
    print(f"TEST TX: {test_tx.to_json()}")

    test_coinbase = Coinbase(script_sig=bytes.fromhex("deadbeef"), outputs=[])
    print(test_coinbase.to_json())

    tx_with_magic_bytes = bytes.fromhex(
        "")
    mb_tx = Transaction.from_bytes(tx_with_magic_bytes)
