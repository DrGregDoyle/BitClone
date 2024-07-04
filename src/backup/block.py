"""
A module for the Block and related classes
"""

from src.backup.merkle import create_merkle_tree
from src.transaction import hash256, CompactSize, decode_transaction


def reverse_bytes(data: bytes):
    hex_data = data.hex()
    reverse_hex_data = "".join([hex_data[x:x + 2] for x in reversed(range(0, len(hex_data), 2))])
    return bytes.fromhex(reverse_hex_data)


class Header:
    VERSION = 0x20000000
    VERSION_BYTES = 4
    PREVIOUS_BLOCK_BYTES = 32
    MERKLE_ROOT_BYTES = 32
    TIME_BYTES = 4
    BITS_BYTES = 4
    NONCE_BYTES = 4

    def __init__(self, prev_block: str | bytes, merkle_root: str | bytes, time: int | bytes, nonce: int | bytes,
                 bits: str | bytes, version=VERSION):
        # previous block | assume hex/bytes in natural byte order
        self.prev_block = bytes.fromhex(prev_block) if isinstance(prev_block, str) else prev_block

        # merkle root | assume hex/bytes in natural byte order
        self.merkle_root = bytes.fromhex(merkle_root) if isinstance(merkle_root, str) else merkle_root

        # time/nonce/bits/version | convert int to 4-byte little endian value
        self.time = time.to_bytes(length=self.TIME_BYTES, byteorder="little") if isinstance(time, int) else time
        self.bits = reverse_bytes(bytes.fromhex(bits)) if isinstance(bits, str) else bits
        self.nonce = nonce.to_bytes(length=self.NONCE_BYTES, byteorder="little") if isinstance(nonce, int) else nonce
        self.version = version.to_bytes(length=self.VERSION_BYTES, byteorder="little") if isinstance(version,
                                                                                                     int) else version

    @property
    def bytes(self):
        return self.version + self.prev_block + self.merkle_root + self.time + self.bits + self.nonce

    @property
    def hex(self):
        return self.bytes.hex()

    @property
    def id(self):
        return hash256(self.bytes).hex()


def decode_header(data: str | bytes):
    data = data.hex() if isinstance(data, bytes) else data  # Data is now a hex string

    # header chars
    version_chars = 2 * Header.VERSION_BYTES
    prev_block_chars = 2 * Header.PREVIOUS_BLOCK_BYTES
    merkle_root_chars = 2 * Header.MERKLE_ROOT_BYTES
    time_chars = 2 * Header.TIME_BYTES
    bits_chars = 2 * Header.BITS_BYTES
    nonce_chars = 2 * Header.NONCE_BYTES

    # version
    version = int.from_bytes(bytes.fromhex(data[:version_chars]), byteorder="little")  # little-endian
    index = version_chars

    # prev_block
    prev_block = bytes.fromhex(data[index:index + prev_block_chars])  # Natural byte order
    index += prev_block_chars

    # merkle root
    merkle_root = bytes.fromhex(data[index:index + merkle_root_chars])  # Natural byte order
    index += merkle_root_chars

    # time
    time = int.from_bytes(bytes.fromhex(data[index:index + time_chars]), byteorder="little")  # little-endian
    index += time_chars

    # bits
    bits = bytes.fromhex(data[index:index + bits_chars])  # little-endian
    index += bits_chars

    # nonce
    nonce = int.from_bytes(bytes.fromhex(data[index:index + nonce_chars]), byteorder="little")  # little-endian
    index += nonce_chars

    # Verify
    original = data[:index]
    temp_header = Header(prev_block=prev_block, merkle_root=merkle_root, time=time, bits=bits, nonce=nonce,
                         version=version)
    if temp_header.hex != original:
        raise ValueError("Constructed Header does not agree with original data.")
    return temp_header


class Block:
    VERSION = 4

    def __init__(self, prev_block: str | bytes, transactions: list, time: int | bytes, bits: str | bytes,
                 nonce: int | bytes, version=VERSION):
        # Transactions
        tx_count = len(transactions)
        self.tx_count = CompactSize(tx_count)
        self.txs = bytes()
        for t in transactions:
            self.txs += t.bytes

        # Calc merkle root
        tx_id_list = [t.txid.hex() for t in self.tx_list()]
        merkle_tree = create_merkle_tree(tx_id_list)
        self.merkle_root = bytes.fromhex(merkle_tree.get(0))

        # Header
        self.header = Header(prev_block, self.merkle_root, time, nonce, bits, version)

    def tx_list(self):
        _tx_list = []
        data = self.txs
        index = 0
        for _ in range(self.tx_count.num):
            temp_tx = decode_transaction(data[index:])
            print(f"TEMP TX HEX: {temp_tx.hex}")
            _tx_list.append(temp_tx)
            index += len(temp_tx.hex)
        return _tx_list


# --- TESTING

if __name__ == "__main__":
    segwit = choice([True, False])
    print(f"SEGWIT: {segwit}")
    # tx1 = fixed_tx(1, segwit=True)
    # tx2 = fixed_tx(2, segwit=True)
    tx1 = random_tx(segwit=segwit, input_num=2, output_num=1)
    tx2 = random_tx(segwit=segwit, input_num=2, output_num=1)
    tx_list = [tx1, tx2]
    print(f"TX1 HEX: {tx1.hex}")
    print(f"TX2 HEX: {tx2.hex}")

    version = 1
    prev_block = hash256("Hello World".encode()).hex()
    time = 1720120296
    bits = "17035d25"
    nonce = pow(2, 16) - 1

    test_block = Block(prev_block, tx_list, time, bits, nonce, version)
