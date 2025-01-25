"""
Classes for the Tx elements
"""
import json

from src.library.data_handling import BTCDataType, BTCData


# Input
class Input:
    TXID_BYTES = 32
    VOUT_BYTES = 4
    SEQ_BYTES = 4

    def __init__(self,
                 tx_id: BTCDataType,
                 v_out: BTCDataType,
                 script_sig: BTCDataType,
                 sequence: BTCDataType = BTCData("0xfffffffd")
                 ):
        self.tx_id = BTCData(tx_id, self.TXID_BYTES)  # 32 bytes | Natural byte order
        self.v_out = BTCData(v_out, self.VOUT_BYTES, "little")  # 4 bytes | Little endian
        self.script_sig = BTCData(script_sig)
        self.script_sig_size = self.script_sig.compact_size()  # Compact Size byte encoding
        self.sequence = BTCData(sequence, self.SEQ_BYTES, "little")  # 4 bytes | little endian

    def __repr__(self):
        """
        Returns json formatted dict
        """
        return self.to_json()

    @property
    def bytes(self):
        """
        Return bytes representation of the input object
        """
        return self.tx_id.bytes + self.v_out.bytes + self.script_sig_size + self.script_sig.bytes + self.sequence.bytes

    @property
    def hex(self):
        """
        Returns hex representation of the input object
        """
        return self.bytes.hex()

    def to_json(self):
        input_dict = {
            "tx_id": self.tx_id.hex,
            "v_out": self.v_out.hex,
            "script_sig_size": self.script_sig_size.hex(),
            "script_sig": self.script_sig.hex,
            "sequence": self.sequence.hex
        }
        return json.dumps(input_dict, indent=2)


class Output:
    AMOUNT_BYTES = 8

    def __init__(self,
                 amount: BTCDataType,
                 script_pubkey: BTCDataType
                 ):
        self.amount = BTCData(amount, self.AMOUNT_BYTES, "little")  # 8 bytes | little-endian
        self.script_pubkey = BTCData(script_pubkey)
        self.script_pubkey_size = self.script_pubkey.compact_size()  # CompactSize bytes encoding

    def __repr__(self):
        return self.to_json()

    @property
    def bytes(self):
        return self.amount.bytes + self.script_pubkey_size + self.script_pubkey.bytes

    @property
    def hex(self):
        return self.bytes.hex()

    def to_json(self):
        output_dict = {
            "amount": self.amount.hex,
            "script_pubkey_size": self.script_pubkey_size.hex(),
            "script_pubkey": self.script_pubkey.hex
        }
        return json.dumps(output_dict, indent=2)


class Witness:

    def __init__(self, *args: BTCDataType):
        """
        Initializes a Witness object.

        Args:
            *args (BTCDataType): Items (witness elements) that make up the witness data.
        """
        # Parse witness items as BTCData objects
        self.items = [BTCData(arg) for arg in args]

        # Calculate compact size for each item
        self.item_sizes = [item.compact_size() for item in self.items]

        # Calculate the stack item count
        self.stack_items = BTCData(len(self.items))

    @property
    def bytes(self) -> bytes:
        """
        Returns the byte representation of the witness object.

        The structure includes:
        - CompactSize encoding of the number of stack items.
        - For each item, its CompactSize length followed by its data bytes.
        """
        result = self.stack_items.compact_size()
        for size, item in zip(self.item_sizes, self.items):
            result += size + item.bytes
        return result

    @property
    def hex(self) -> str:
        """
        Returns the hex representation of the witness object.
        """
        return self.bytes.hex()

    def __repr__(self) -> str:
        """
        Returns a JSON-formatted string representation of the witness object.
        """
        witness_dict = {
            "stack_items": self.stack_items.hex
        }

        # Update with each item
        for x in range(self.stack_items.int):
            item_dict = {
                "size": self.item_sizes[x].hex(),
                "item": self.items[x].hex
            }
            witness_dict.update({
                x: item_dict
            })

        return json.dumps(witness_dict, indent=2)


class Transaction:
    VERSION = BTCData(2, 4, "little")  # Version = 2 | 4 bytes, little-endian
    LOCKTIME = BTCData("0xffffffff", 4, "little")  # Locktime = 2^{32} - 1 | 4 bytes, little-endian

    def __init__(self,
                 inputs: list[Input],
                 outputs: list[Output],
                 witnesses: list[Witness] = None,
                 locktime: BTCDataType = LOCKTIME,
                 version: BTCDataType = VERSION
                 ):
        """
        Initializes a Transaction object.

        Args:
            version (BTCDataType): Transaction version (typically 4 bytes, little-endian).
            inputs (list[Input]): List of transaction inputs.
            outputs (list[Output]): List of transaction outputs.
            locktime (BTCDataType): Locktime (4 bytes, little-endian).
            witnesses (list[Witness], optional): List of witnesses. Default is None.
        """
        if not inputs:
            raise ValueError("Transaction must have at least one input.")
        if not outputs:
            raise ValueError("Transaction must have at least one output.")

        self.version = BTCData(version, 4, "little") if not isinstance(version, BTCData) else version
        self.inputs = inputs
        self.outputs = outputs
        self.locktime = BTCData(locktime, 4, "little") if not isinstance(version, BTCData) else locktime
        self.witnesses = witnesses or []

    @property
    def is_segwit(self) -> bool:
        return len(self.witnesses) > 0

    @property
    def bytes(self) -> bytes:
        """
        Returns the byte representation of the transaction.

        The structure includes:
        - Version (4 bytes, little-endian)
        - Input count (CompactSize)
        - Input data
        - Output count (CompactSize)
        - Output data
        - Witnesses (if present)
        - Locktime (4 bytes, little-endian)
        """
        # Serialize version
        result = self.version.bytes

        # Serialize inputs
        result += BTCData(len(self.inputs)).compact_size()
        for tx_input in self.inputs:
            result += tx_input.bytes

        # Serialize outputs
        result += BTCData(len(self.outputs)).compact_size()
        for tx_output in self.outputs:
            result += tx_output.bytes

        # Serialize witnesses (if present)
        if self.witnesses:
            for witness in self.witnesses:
                result += witness.bytes

        # Serialize locktime
        result += self.locktime.bytes

        return result

    @property
    def hex(self) -> str:
        """
        Returns the hex representation of the transaction.
        """
        return self.bytes.hex()

    def __repr__(self) -> str:
        """
        Returns a JSON-formatted string representation of the transaction.
        """
        transaction_dict = {
            "version": self.version.hex,
            "inputs": [json.loads(str(tx_input)) for tx_input in self.inputs],
            "outputs": [json.loads(str(tx_output)) for tx_output in self.outputs],
            "locktime": self.locktime.hex
        }

        # Include witnesses if present
        if self.witnesses:
            transaction_dict["witnesses"] = [json.loads(str(witness)) for witness in self.witnesses]

        return json.dumps(transaction_dict, indent=2)


# --- TESTING
import secrets

if __name__ == "__main__":
    random_txid = "deadbeef"  # 32 random bytes
    random_vout = 1
    script_sig = secrets.token_bytes(64)  # 40 random bytes
    sequence = "fffffffd"
    _input = Input(random_txid, random_vout, script_sig, sequence)
    print(f"INPUT: {_input}")

    random_amount = secrets.token_bytes(8)
    random_script_pubkey = secrets.token_bytes(20)
    _output = Output(random_amount, random_script_pubkey)
    print(f"OUTPUT: {_output}")

    item1 = secrets.token_bytes(20)
    item2 = secrets.token_bytes(20)
    _witness = Witness(item1, item2)
    print(f"WITNESS: {_witness}")

    # Create transaction with default version and locktime
    transaction = Transaction([_input], [_output], [_witness])

    # Display transaction details
    # print("Transaction Bytes:", transaction.bytes)
    print("Transaction Hex:", transaction.hex)
    print("Transaction JSON:", transaction)
