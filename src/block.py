"""
A module for the Block class

    Block Structure
    ======================================================================
    Size                Field                   Description
    ======================================================================
    4 bytes             Block size              The size of the block in bytes
    80 bytes            Block header            Standard Header formatting
    1-3 compactSize     Transaction counter     Number of transactions
    var                 Transactions            The transactions for the block
    ======================================================================
"""
import json
from datetime import datetime
from random import randint

from src.transaction import CompactSize, Transaction, Input, Output, Witness, WitnessItem, match_byte_chunk, \
    decode_transaction
from src.utility import *
from src.wallet import WalletFactory


# --- IMPORTS --- #


def unix_time():
    return datetime.utcnow().timestamp()[::-1]  # Little Endian


# --- CLASSES --- #

class Header:
    """
    Header Fields
    =====================================================================
    |   field               |   size (bytes)    |   format              |
    =====================================================================
    |   version             |   4               |   little-endian       |
    |   previous block hash |   32              |   natural byte order  |
    |   merkle root         |   32              |   natural byte order  |
    |   timestamp           |   4               |   little-endian       |
    |   bits (target)       |   4               |   little-endian       |
    |   nonce               |   4               |   little-endian       |
    =====================================================================

    """
    VERSION_BYTES = 4
    HASH_BYTES = 32
    MERKLE_BYTES = 32
    TIME_BYTES = 4
    TARGET_BYTES = 4
    NONCE_BYTES = 4

    def __init__(self, prev_block: str, merkle_root: str, target: int, nonce: int, timestamp: int | None = None,
                 version=1):
        """
        Todo: Write function to encode target into bits
        """
        # Get and format variables
        self.prev_block = prev_block.zfill(2 * self.HASH_BYTES)
        self.merkle_root = merkle_root.zfill(2 * self.MERKLE_BYTES)

        self.target = format(target, f"0{2 * self.TARGET_BYTES}x")[::-1]  # Little Endian
        self.nonce = format(nonce, f"0{2 * self.NONCE_BYTES}x")[::-1]  # Little Endian
        self.version = format(version, f"0{2 * self.VERSION_BYTES}x")[::-1]  # Little Endian

        # Get time
        if timestamp:
            temp_dt = datetime.fromtimestamp(timestamp / 1e3)
            self.time = int(round(temp_dt.utcnow().timestamp()))
        else:
            self.time = unix_time()
        self.time = format(self.time, f"0{2 * self.TIME_BYTES}x")[::-1]  # Little Endian

    @property
    def encoded(self):
        return self.version + self.prev_block + self.merkle_root + self.time + self.target + self.nonce

    @property
    def id(self):
        return sha256(self.encoded.encode()).hexdigest()

    def to_json(self):
        header_dict = {
            "version": self.version,
            "prev_block": self.prev_block,
            "merkle_root": self.merkle_root,
            "time": self.time,
            "target": self.target,
            "nonce": self.nonce
        }
        return json.dumps(header_dict, indent=2)


def decode_header(header_string: str) -> Header:
    # Get chars
    version_chars = 2 * Header.VERSION_BYTES
    hash_chars = 2 * Header.HASH_BYTES
    merkle_chars = 2 * Header.MERKLE_BYTES
    time_chars = 2 * Header.TIME_BYTES
    target_chars = 2 * Header.TARGET_BYTES
    nonce_chars = 2 * Header.NONCE_BYTES

    # Version
    version = header_string[:version_chars]
    current_index = version_chars
    version_int = int(version[::-1], 16)

    # Previous Block
    prev_block = header_string[current_index:current_index + hash_chars]
    current_index += hash_chars

    # Merkle Root
    merkle_root = header_string[current_index: current_index + merkle_chars]
    current_index += merkle_chars

    # Time
    timestamp = header_string[current_index:current_index + time_chars]
    current_index += time_chars
    timestamp_int = int(timestamp[::-1], 16)

    # target
    target = header_string[current_index:current_index + target_chars]
    current_index += target_chars
    target_int = int(target[::-1], 16)

    # nonce
    nonce = header_string[current_index:current_index + nonce_chars]
    nonce_int = int(nonce[::-1], 16)

    # Verify
    constructed_encoding = version + prev_block + merkle_root + timestamp + target + nonce
    constructed_header = Header(prev_block=prev_block, merkle_root=merkle_root, target=target_int, nonce=nonce_int,
                                timestamp=timestamp_int, version=version_int)
    if constructed_header.encoded != constructed_encoding:
        raise TypeError("Given input string did not generate same Header object")
    return constructed_header


class Block:

    def __init__(self, header: Header, tx_list: list):
        # Header
        self.header = header

        # TXs
        self.tx_count = CompactSize(len(tx_list))
        self.tx_list = tx_list

    @property
    def block_hash(self):
        return self.header.id

    @property
    def encoded(self):
        encoded_string = self.header.encoded
        encoded_string += self.tx_count.encoded
        for tx in self.tx_list:
            encoded_string += tx.encoded
        return encoded_string

    def to_json(self):
        block_dict = {
            "header": json.loads(self.header.to_json()),
        }
        tx_dict = {}
        for x in range(len(self.tx_list)):
            temp_tx = self.tx_list[x]
            tx_dict.update({x: json.loads(temp_tx.to_json())})
        block_dict.update({"txs": tx_dict})
        return json.dumps(block_dict, indent=2)


def decode_block(block_string: str):
    # Header
    header = decode_header(block_string)

    # Txs
    current_index = len(header.encoded)
    byte_chunk = block_string[current_index:current_index + 2]
    current_index += 2
    increment = match_byte_chunk(byte_chunk)
    tx_num = block_string[current_index:current_index + increment] if increment else byte_chunk
    current_index += increment
    tx_int = int(tx_num, 16)
    tx_list = []
    tx_verify_string = ""
    for _ in range(tx_int):
        temp_tx = decode_transaction(block_string[current_index:])
        tx_list.append(temp_tx)
        current_index += len(temp_tx.encoded)
        tx_verify_string += temp_tx.encoded

    # Verify
    constructed_encoding = header.encoded + tx_num + tx_verify_string
    constructed_block = Block(header=header, tx_list=tx_list)
    if constructed_block.encoded != constructed_encoding:
        raise TypeError("Given input string did not generate same Block object")
    return constructed_block


# --- TESTING --- #

def random_header() -> Header:
    prev_block = random_tx_id()
    merkle_root = random_hash256()
    target = random_integer(4)
    test_time = random_integer(4)
    nonce = random_integer(4)
    return Header(prev_block=prev_block, merkle_root=merkle_root, target=target, nonce=nonce,
                  timestamp=test_time)


def random_tx() -> Transaction:
    random_wallet = WalletFactory().new_wallet()

    # Inputs
    random_num_inputs = randint(1, 3)
    input_list = []
    for _ in range(random_num_inputs):
        tx_id = random_tx_id()
        v_out = random_v_out()
        script_sig = random_wallet.sign_transaction(tx_id=tx_id)
        temp_input = Input(tx_id, v_out, script_sig)
        input_list.append(temp_input)

    # Outputs
    random_num_outputs = randint(1, 3)
    output_list = []
    for _ in range(random_num_outputs):
        amount = random_amount()
        output_script = hash160(random_tx_id())
        temp_output = Output(amount, output_script)
        output_list.append(temp_output)

    # Witness
    witness_list = []
    for _ in range(random_num_inputs):
        item_list = []
        random_num_items = randint(1, 3)
        for _ in range(random_num_items):
            item = random_tx_id()
            witness_item = WitnessItem(item)
            item_list.append(witness_item)
        temp_witness = Witness(item_list)
        witness_list.append(temp_witness)

    # Return Transaction
    return Transaction(inputs=input_list, outputs=output_list, witness_list=witness_list)


if __name__ == "__main__":
    test_header = random_header()
    tx1 = random_tx()
    tx2 = random_tx()
    block = Block(header=test_header, tx_list=[tx1, tx2])
    print(block.to_json())

    constructed_block = decode_block(block.encoded)
    print("========")
    print(constructed_block.to_json())
