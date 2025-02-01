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


class Serializable:
    """
    A base class that defines the interface for serializing and
    deserializing data to and from Bitcoin's wire format.
    """
    __slots__ = ()

    @classmethod
    def from_bytes(cls, byte_stream):
        """
        Parse the given byte_stream (a bytes object or a file-like object)
        and return an instance of cls.
        """
        raise NotImplementedError

    @classmethod
    def from_hex(cls, hex_string: str):
        """
        Parse the given hex string and return an instance of cls using the from_bytes method
        """
        raise NotImplementedError

    def to_bytes(self) -> bytes:
        """ Serialize this object into Bitcoin's wire format. """
        raise NotImplementedError

    def to_dict(self) -> dict:
        """ Convert the object to a dictionary (must be implemented in subclasses). """
        raise NotImplementedError

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

    @classmethod
    def from_hex(cls, hex_str: str) -> 'Input':
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
        Serialize this input into bytes according to Bitcoin's transaction input format.

        Returns:
            bytes: The serialized transaction input.
        """
        # Pack fixed-size fields
        fixed_part = self._struct.pack(self.txid, self.vout)

        # Pack script_sig (variable size)
        script_sig_part = write_compact_size(len(self.script_sig)) + self.script_sig

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
        Serialize this output into bytes according to Bitcoin's transaction output format.
        Example pseudo-steps:
          1. value (8 bytes)
          2. CompactSize for scriptPubKey length, then script_pubkey
        """
        amount_bytes = self.amount.to_bytes(self.AMOUNT_BYTES, byteorder="little")
        script_pubkey_bytes = write_compact_size(len(self.script_pubkey)) + self.script_pubkey
        return amount_bytes + script_pubkey_bytes

    def to_dict(self) -> dict:
        """
        Convert the Output to a dictionary for easy inspection.

        Returns:
            dict: A dictionary representation of the Output.
        """
        return {
            "amount": self.amount.to_bytes(self.AMOUNT_BYTES, byteorder="little").hex(),
            "script_pubkey_size": write_compact_size(len(self.script_pubkey)).hex(),
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

    @classmethod
    def from_hex(cls, hex_stream):
        clean_string = check_hex(hex_stream)
        return cls.from_bytes(bytes.fromhex(clean_string))

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

    def __init__(self, items=None):
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
    __slots__ = ('version', 'inputs', 'outputs', 'locktime', 'witnesses', 'input_count', 'output_count')
    VERSION_BYTES = 4
    LOCKTIME_BYTES = 4
    MARKER = b'\x00'
    FLAG = b'\x01'

    def __init__(self, version: int, inputs=None, outputs=None, locktime: int = 0, witnesses=None):
        if inputs is None:
            inputs = []
        if outputs is None:
            outputs = []
        if witnesses is None:
            witnesses = []

        self.version = version
        self.inputs = inputs
        self.outputs = outputs
        self.locktime = locktime
        self.witnesses = witnesses

        # Get input and output counts
        self.input_count = write_compact_size(len(self.inputs))
        self.output_count = write_compact_size(len(self.outputs))

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
        if len(version_data) != 4:
            raise ValueError("Insufficient data for version.")
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
            new_input = Input.from_bytes(stream)
            inputs.append(new_input)
            # input_data_length = read_compact_size(stream)
            # input_data = stream.read(input_data_length)
            # inputs.append(Input.from_bytes(input_data))

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
                # witness_data_length = read_compact_size(stream)
                # witness_data = stream.read(witness_data_length)
                # witnesses.append(Witness.from_bytes(witness_data))

        # Read locktime (4 bytes, little-endian)
        locktime_data = stream.read(4)
        if len(locktime_data) != 4:
            raise ValueError("Insufficient data for locktime.")
        locktime = int.from_bytes(locktime_data, byteorder="little")

        return cls(version, inputs, outputs, locktime, witnesses)

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
        version_bytes = self.version.to_bytes(self.VERSION_BYTES, byteorder="little")

        is_segwit = len(self.witnesses) > 0
        if is_segwit:
            marker_flag_bytes = self.MARKER + self.FLAG
        else:
            marker_flag_bytes = b''

        inputs_bytes = write_compact_size(len(self.inputs))
        for i in self.inputs:
            inputs_bytes += i.to_bytes()

        outputs_bytes = write_compact_size(len(self.outputs))
        for o in self.outputs:
            outputs_bytes += o.to_bytes()

        witnesses_bytes = b''
        if is_segwit:
            for witness in self.witnesses:
                witnesses_bytes += witness.to_bytes()

        locktime_bytes = self.locktime.to_bytes(self.LOCKTIME_BYTES, byteorder="little")

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
        tx_dict["inputcount"] = write_compact_size(len(self.inputs)).hex()
        tx_dict["inputs"] = [i.to_dict() for i in self.inputs]
        tx_dict["outputcount"] = write_compact_size(len(self.outputs)).hex()
        tx_dict["outputs"] = [i.to_dict() for i in self.outputs]

        # 4. If SegWit, add witness
        if self.is_segwit:
            tx_dict["witnesses"] = [w.to_dict() for w in self.witnesses]

        # 5. Add locktime and return
        tx_dict["locktime"] = self.locktime.to_bytes(self.LOCKTIME_BYTES, "little").hex()
        return tx_dict


# -- TESTING
if __name__ == "__main__":
    # _test_txid = bytes.fromhex("deadbeef")
    # _test_vout = 1
    # _test_scriptsig = bytes.fromhex("aabbccddeeff001122334455667788990ab5e5")
    # _test_sequence = 0xfffffffd
    # _test_input = Input(_test_txid, _test_vout, _test_scriptsig, _test_sequence)
    # print(f"TEST INPUT: {_test_input}")

    # _knownidhex = "9945a5a440f2d3712ff095cb1efefada1cc52e139defedb92a313daed49d5678010000006a473044022031b6a6b79c666d5568a9ac7c116cacf277e11521aebc6794e2b415ef8c87c899022001fe272499ea32e6e1f6e45eb656973fbb55252f7acc64e1e1ac70837d5b7d9f0121023dec241e4851d1ec1513a48800552bae7be155c6542629636bcaa672eee971dcffffffff"
    # _knowninput = Input.from_hex(_knownidhex)
    # print(f"KNOWN INPUT: {_knowninput}")
    # _recovered_input = Input.from_hex(_knowninput.to_bytes().hex())
    # print(f"RECOVERED INPUT: {_recovered_input}")

    _witness_item1 = WitnessItem(bytes.fromhex("deadbeef"))
    _witness_item2 = WitnessItem(bytes.fromhex("badcaddad0"))
    _witness = Witness([_witness_item1, _witness_item2])
    print(_witness)
    _witness_bytes = _witness.to_bytes()
    _recovered_witness = Witness.from_bytes(_witness_bytes)
    print(_recovered_witness)
    #
    # _learn_me_input_hex = "9945a5a440f2d3712ff095cb1efefada1cc52e139defedb92a313daed49d5678010000006a473044022031b6a6b79c666d5568a9ac7c116cacf277e11521aebc6794e2b415ef8c87c899022001fe272499ea32e6e1f6e45eb656973fbb55252f7acc64e1e1ac70837d5b7d9f0121023dec241e4851d1ec1513a48800552bae7be155c6542629636bcaa672eee971dcffffffff"
    # _recoved_input = Input.from_bytes(bytes.fromhex(_learn_me_input_hex))
    # print(f"RECOVERED INPUT: {_recoved_input}")
    #
    # _learn_me_output_hex = "00e1f505000000001976a914299da5537e8b65bf45c70a9ece75988ebfca86b588ac"
    # _recovered_output = Output.from_bytes(bytes.fromhex(_learn_me_output_hex))
    # print(f"RECOVERED OUTPUT: {_recovered_output}")

    # BASIC_LEGACY_TX_HEX = "010000000110ddd830599b17cc690535f7df28a84466eaca3c22f0d55b79023b6570f4fbc5010000008b483045022100e6186d6f344ce4df46b2e15d87093d34edbf5b50462b6b45f9bd499a6a62fbc4022055f56a1c4a24ea6be61564593c4196b47478a25cf596c1baf59f5a9a229b637c014104a41e997b6656bc4f5dd1f9b9df3b4884cbec254d3b71d928587695b0df0a80417432f4ca6276bc620b1f04308e82e70015a40f597d8260912f801e4b62ab089effffffff0200e9c829010000001976a9146f34d3811aded1df870359f311c2a11a015e945388ac00e40b54020000001976a91470d6734de69c1ac8913892f2df9be0e738d26c2d88ac00000000"
    # BASIC_SEGWIT_TX_HEX = "010000000001013c735f81c1a0115af2e735554fb271ace18c32a3faf443f9db40cb9a11ca63110000000000ffffffff02b113030000000000160014689a681c462536ad7d735b497511e527e9f59245cf120000000000001600148859f1e9ef3ba438e2ec317f8524ed41f8f06c6a024730440220424772d4ad659960d4f1b541fd853f7da62e8cf505c2f16585dc7c8cf643fe9a02207fbc63b9cf317fc41402b2e7f6fdc1b01f1b43c5456cf9b547fe9645a16dcb150121032533cb19cf37842556dd2168b1c7b6f3a70cff25a6ff4d4b76f2889d2c88a3f200000000"
    # ADVANCED_TX_HEX = "01000000000102f11271713fb911ebdb7daa111470853084c5b4f6ad73582517a73b1131839d71000000006a473044022001187384d8b30020a0ad6976805f0676da8e5fd219ffec084f7c22d2acd4838f0220074e3195a6e624b7ac5cb8e072d77f3b6363968040fc99f268affd4c08e11ac7012103510f10304c99bd53af8b3e47b3e282a75a50dad6f459c4c985898fd800a9e9a8fffffffff11271713fb911ebdb7daa111470853084c5b4f6ad73582517a73b1131839d710100000000ffffffff021027000000000000160014858e1f88ff6f383f45a75088e15a095f20fc663f2c1a0000000000001976a9142241a6c3d4cc3367efaa88b58d24748caef79a7288ac0002473044022035345342616cb5d6eefbbffc1de179ee514587dd15efe5ca892602f50336e30502207864061776e39992f317aee92dcc9595cc754b8f13957441d5ccd9ebd1b5cc0c0121022ed6c7d33a59cc16d37ad9ba54230696bd5424b8931c2a68ce76b0dbbc222f6500000000"
    # _learn_me_tx_hex = "0100000002c03b4640baf8e919d9984be0c882fb235df843d33e2eda84e890e3d4143158a9010000006b483045022100dde67b86d5ecd58669635fe7bd5bf83d3b60c1a118f84a4afc3f5f8eaaa4ba68022020e41869e45bb08d241be7b95169dd96a556f52db265eee98d26a8a8b9a9c93e012102da87884e3f9933a3f5bc7c5bc304f3a0ec2f05384b412308cfe0bbc9db70c97ffeffffffacfc00ac820d822d999bdfa8fa4f4b9199faced9c5b328abfb5d34792d590d00040000006b483045022100fdf59d8675914bfb7ff89ae4a133610653f85b58a39b6404a2705ff97d10865102200bdebecf495706cdc114be0435e06999b7f9eef3cb94baa5f83fe252fc2a5dfe01210257827e31f30bb63ab05960c4d9ade1708b60b8e196a39ad038f660477ac1a2ddfeffffff02dc190500000000001976a914a8cffc755b5ba95e79ece8036a044e9b4dceb51f88acdd821100000000001976a914751279ece361265d0acd00c69d1b5f40afb3ad7488ac517c0600"
    # _recovered_tx = Transaction.from_hex(_learn_me_tx_hex)
    # print(f"RECOVERED TX: {_recovered_tx}")
