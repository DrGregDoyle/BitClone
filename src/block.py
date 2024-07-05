"""
A module for the Block and related classes
"""
import json

from src.cryptography import hash256, reverse_bytes


class Header:
    """
    =========================================================
    |   field       |   size (bytes)|   format              |
    =========================================================
    |   version     |   4           |   little-endian       |
    |   prev_block  |   32          |   natural byte order  |
    |   merkle_root |   32          |   natrual byte order  |
    |   time        |   4           |   little-endian       |
    |   bits        |   4           |   little-endian       |
    |   nonce       |   4           |   little-endian       |
    =========================================================
    """
    PREVBLOCK_BYTES = 32
    MERKLE_BYTES = 32
    TIME_BYTES = 4
    BITS_BYTES = 4
    NONCE_BYTES = 4
    VERSION_BYTES = 4
    VERSION = 2

    def __init__(self, prev_block: str | bytes, merkle_root: str | bytes, time: int | bytes, bits: str | bytes,
                 nonce: int | bytes, version: int | bytes = VERSION):
        # previous block | 32 bytes
        _prev_block = prev_block.hex() if isinstance(prev_block, bytes) else prev_block
        self.prev_block = int(_prev_block, 16).to_bytes(length=self.PREVBLOCK_BYTES, byteorder="little")

        # merkle root | 32 bytes
        _merkle_root = merkle_root.hex() if isinstance(merkle_root, bytes) else merkle_root
        self.merkle_root = int(_merkle_root, 16).to_bytes(length=self.MERKLE_BYTES, byteorder="little")

        # time | 4 bytes
        _time = int(time.hex(), 16) if isinstance(time, bytes) else time
        self.time = _time.to_bytes(length=self.TIME_BYTES, byteorder="little")

        # bits | 4 bytes
        _bits = bits.hex() if isinstance(bits, bytes) else bits
        self.bits = int(_bits, 16).to_bytes(self.BITS_BYTES, byteorder="little")

        # nonce | 4 bytes
        _nonce = int(nonce, 16) if isinstance(nonce, bytes) else nonce
        self.nonce = _nonce.to_bytes(length=self.NONCE_BYTES, byteorder="little")

        # version | 4 bytes
        _version = version.hex() if isinstance(version, bytes) else version
        self.version = _version.to_bytes(length=self.VERSION_BYTES, byteorder="little")

    @property
    def bytes(self):
        return self.version + self.prev_block + self.merkle_root + self.time + self.bits + self.nonce

    @property
    def hex(self):
        return self.bytes.hex()

    @property
    def id(self):
        return hash256(self.bytes)

    def to_json(self):
        header_dict = {
            "block_hash": reverse_bytes(self.id),  # reverse byte order
            "version": self.version.hex(),
            "prev_block": self.prev_block.hex(),
            "merkle_root": self.merkle_root.hex(),
            "time": self.time.hex(),
            "bits": self.bits.hex(),
            "nonce": self.nonce.hex()
        }
        return json.dumps(header_dict, indent=2)


# --- TESTING

if __name__ == "__main__":
    # tx1 = random_tx()
    # tx2 = random_tx()
    # merkle_tree = create_merkle_tree([tx1.txid, tx2.txid])
    # merkle_root = merkle_tree.get(0)
    #
    # prev_block = random_bytes(byte_length=32).hex()
    #
    # time = int(random_bytes().hex(), 16)
    # bits = random_bytes().hex()
    # nonce = int(random_bytes().hex(), 16)
    # version = int(random_bytes().hex(), 16)
    #
    # h = Header(prev_block, merkle_root, time, bits, nonce, version)
    # print(h.to_json())
    # h1 = decode_header(h.bytes)
    # h2 = decode_header(h.hex)
    #
    # assert h1.bytes == h.bytes
    # assert h2.bytes == h.bytes

    raw_header = "00e032302210e4470cc86729ce6d0077872dc15953ec67e429ca030000000000000000006c110edc66b0dcf8ae072323c9b515539a4c1119ccc25b1d6848abb238ee2af2f3aa3764b2e00517b8d166ab"
    h = decode_header(raw_header)
    print(h.to_json())

#
#
# class Block:
#     VERSION = 4
#
#     def __init__(self, prev_block: str | bytes, transactions: list, time: int | bytes, bits: str | bytes,
#                  nonce: int | bytes, version=VERSION):
#         # Transactions
#         tx_count = len(transactions)
#         self.tx_count = CompactSize(tx_count)
#         self.txs = bytes()
#         for t in transactions:
#             self.txs += t.bytes
#
#         # Calc merkle root
#         tx_id_list = [t.txid.hex() for t in self.tx_list()]
#         merkle_tree = create_merkle_tree(tx_id_list)
#         self.merkle_root = bytes.fromhex(merkle_tree.get(0))
#
#         # Header
#         self.header = Header(prev_block, self.merkle_root, time, nonce, bits, version)
#
#     def tx_list(self):
#         _tx_list = []
#         data = self.txs
#         index = 0
#         for _ in range(self.tx_count.num):
#             temp_tx = decode_transaction(data[index:])
#             print(f"TEMP TX HEX: {temp_tx.hex}")
#             _tx_list.append(temp_tx)
#             index += len(temp_tx.hex)
#         return _tx_list
#
#
