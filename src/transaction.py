"""
A page for the Transaction class

Notes:
    -If using segwit, the marker must be zero (0x00) and the flag must be nonzero (0x01).
    -If not using segwit, the marker and flag must not be included in the transaction
    -The unit of measurement for Bitcoin is called "weight". We say that 4 weight = 1 vbyte.
    -To calculate the weight of a field in a transaction, multiply the byte size of the field by the associated factor
        =====               =====
        Field               Factor
        -----               -----
        Version             4
        Marker/Flag         1
        Inputs Count        4
        Outpoint            4
        Input Script        4
        Sequence            4
        Outputs Count       4
        Amount              4
        Output Script       4
        Witness Count       1
        Witness Items       1
        Lock Time           4
        -----               -----

 === Structure of a transaction ===
    Version: 4 bytes
    Marker: segwit optional 1 byte
    Flag: segwit optional 1 byte
    Inputs:
        --
        count: compactSize unsigned integer (variable integer)
        outpoint:
            --
            txid: 32 byte
            output_index: 4 byte (index starting at 0)
        input script:
        sequence:
    Outputs:
        --
        count: compactSize integer (greater than 0)
        amount/value: 8-byte *signed* integer (min = 0, max = 21 000 000 000 000 000)
        script_length: compactSize integer
    Witness:
        --
        count: compactSize integer
    Lock Time:

"""
# --- IMPORTS --- #
import logging
import sys

from src.utility import hash

# --- LOGGING --- #
log_level = logging.DEBUG
logger = logging.getLogger(__name__)
logger.setLevel(log_level)
logger.addHandler(logging.StreamHandler(stream=sys.stdout))


# --- CLASSES --- #

class CompactSize:

    def __init__(self, n: int):
        """
        Given a non-negative integer n we return a variable length encoding of maximum 9 byte length
        """
        self.unencoded = n
        self.encoded = self.get_encoding()
        self.byte_length = (len(self.encoded) - 2) // 2

    def get_encoding(self):
        """
        We return the encoding of n assuming 0 <= n < 2^32
        """
        # Get hex value and prepend string
        hex_val = hex(self.unencoded)
        raw_hex = hex_val[2:]
        prepend = hex_val[:2]

        # Modify raw_hex and prepend based on size
        if 0 <= self.unencoded <= 0xFC:
            raw_hex = raw_hex.zfill(2)  # Make a 1 byte string = 2 hex chars
        elif 0xFD <= self.unencoded <= 0xFFFF:
            raw_hex = raw_hex.zfill(4)
            prepend += "FD"
        elif 0X10000 <= self.unencoded <= 0xFFFFFFFF:
            raw_hex = raw_hex.zfill(8)
            prepend += "FE"
        elif 0x100000000 <= self.unencoded <= 0xffffffffffffffff:
            raw_hex = raw_hex.zfill(16)
            prepend += "FF"

        # Return prepend string + hex string of number
        return prepend + raw_hex


class Outpoint:
    """
    Used as reference to previous UTXO
    """
    INDEX_BYTES = 4

    def __init__(self, txid: str, output_index: int):
        # Get tx_id
        self.txid = txid

        # Get output index and format it
        self.index_int = output_index
        self.index = format(self.index_int, f"0{2 * self.INDEX_BYTES}x")

    @property
    def encoded(self):
        return self.txid + self.index


class Input:
    """
    Inputs for Transactions
    """
    SEQUENCE_BYTES = 4

    def __init__(self, outpoint: Outpoint, input_script: str, sequence: int):
        self.outpoint = outpoint
        self.script_length = CompactSize(len(input_script))
        self.script = input_script
        self.sequence = sequence

    @property
    def encoded(self):
        return (self.outpoint.encoded + self.script_length.encoded + self.script +
                format(self.sequence, f"0{2 * self.SEQUENCE_BYTES}x"))


class Output:
    """
    Outputs for Transactions
    """
    AMOUNT_BYTES = 8

    def __init__(self, amount: int, output_script: str):
        # Get amount and format it
        self.amount_int = amount
        self.amount = format(amount, f"0{2 * self.AMOUNT_BYTES}x")

        # Get output script along with length of script
        self.script = output_script
        self.script_length = CompactSize(len(self.script))

    @property
    def encoded(self):
        return self.amount + self.script_length.encoded + self.script


class Transaction:
    VERSION = 4  # 4 bytes for version field

    def __init__(self, inputs: list, outputs: list):
        """
        We assume the inputs list is not empty.
        """
        # Get lists
        self.inputs = inputs
        self.outputs = outputs

        # Get size of lists as compactSize elements
        self.num_inputs = CompactSize(len(self.inputs))
        self.num_outputs = CompactSize(len(self.outputs))


# --- TESTING --- #
if __name__ == "__main__":
    number = 65537
    cs = CompactSize(number)
    print(cs.unencoded)
    print(cs.encoded)
    print(cs.byte_length)
    hash1 = hash("String1")
    hash2 = hash("String2")
    outpoint1 = Outpoint(hash1, 1)
    print(outpoint1)
    print(outpoint1.txid)
    print(outpoint1.index)
