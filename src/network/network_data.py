"""
Classes for different types of Network data structures

    - Differentially encoded classes:
        - BlockTransactionsRequest
        - HeaderAndShortIDs
        - PrefilledTx


"""
import siphash

from src.blockchain.block import BlockHeader
from src.core import Serializable, SERIALIZED, get_stream, read_little_int, read_stream, read_big_int, \
    read_compact_size, NetworkDataError
from src.cryptography.hash_functions import sha256
from src.data import IP_ADDRESS, ip_from_netaddr, write_compact_size, BitIP, decode_differential, encode_differential
from src.network.network_types import Services, InvType
from src.tx.tx import Transaction

__all__ = ["BlockTransactions", "NetAddr", "InvVector", "PrefilledTx", "ShortIDs", "HeaderAndShortIDs",
           "BlockTransactionsRequest"]


class NetAddr(Serializable):
    """
    The standard format of a network address
    -----------------------------------------------------------------
    |   Name            | Data type | Formatted             | Size  |
    -----------------------------------------------------------------
    |   time*           | int       | little-endian         | 4     |
    |   Services        | bytes     | little-endian         | 8     |
    |   ip address      | ipv6      | network byte order    | 16    |
    |   port            | int       | network byte order    | 2     |
    -----------------------------------------------------------------
    *time not present in version message
    """

    def __init__(self, time: int | None, services: Services, ip_addr: IP_ADDRESS | str, port: int,
                 is_version: bool = False):
        self.time = None if is_version else time
        self.services = services
        self.ip_addr = BitIP(ip_addr)
        self.port = port

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED, is_version: bool = False):
        stream = get_stream(byte_stream)

        # Time
        if not is_version:
            time = read_little_int(stream, 4)
        else:
            time = None

        # Services
        service_int = read_little_int(stream, 8)
        services = Services(service_int)

        # IP address
        ip_bytes = read_stream(stream, 16)
        ip_addr = ip_from_netaddr(ip_bytes)

        # port
        port = read_big_int(stream, 2)

        return cls(time, services, ip_addr, port)

    def to_bytes(self) -> bytes:
        parts = [
            self.time.to_bytes(4, "little") if self.time else b'',
            self.services.to_bytes(8, "little"),
            self.ip_addr.to_bytes(),
            self.port.to_bytes(2, "big")
        ]
        return b''.join(parts)

    def to_dict(self, formatted: bool = True):
        if self.time:
            time_val = self.time.to_bytes(4, "little").hex() if formatted else self.time
        else:
            time_val = ""
        return {
            "time": time_val,
            "serivces": self.services.name,
            "ip_addr": self.ip_addr.to_bytes().hex() if formatted else self.ip_addr.ip,
            "port": self.port.to_bytes(2, "big").hex() if formatted else self.port
        }


class InvVector(Serializable):
    """
    The inventory vector data structure
    """

    def __init__(self, inv_type: int | InvType, obj_hash: bytes):
        # Validation
        if isinstance(inv_type, int):
            # Check if the integer corresponds to a valid InvType value
            valid_values = {member.value for member in InvType}
            if inv_type not in valid_values:
                raise ValueError(f"Invalid inv_type: {inv_type}. Must be one of {sorted(valid_values)}")
            self.type = InvType(inv_type)
        elif isinstance(inv_type, InvType):
            self.type = inv_type
        else:
            raise TypeError(f"inv_type must be int or InvType, got {type(inv_type)}")

        # Validate hash length
        if not isinstance(obj_hash, bytes):
            raise TypeError(f"obj_hash must be bytes, got {type(obj_hash)}")
        if len(obj_hash) != 32:
            raise ValueError(f"obj_hash must be exactly 32 bytes, got {len(obj_hash)}")

        self.hash = obj_hash

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # inv_type = 4 byte little-endian int
        int_type = read_little_int(stream, 4)

        # hash = 32 bytes
        obj_hash = read_stream(stream, 32)

        return cls(int_type, obj_hash)

    def to_bytes(self) -> bytes:
        parts = [
            self.type.to_bytes(4, "little"),
            self.hash
        ]
        return b''.join(parts)

    def to_dict(self, formatted: bool = True) -> dict:
        return {
            "type": self.type.value if formatted else self.type.name,
            "hash": self.hash.hex()
        }


class PrefilledTx(Serializable):
    """
    =====================================================================
    |   name        |   data type   |   format          |   byte size   |
    =====================================================================
    |   block_index |   int         |   compactSize*    |   1 or 3      |
    |   tx          |   Transaction |   tx.to_bytes()   |   var         |
    =====================================================================
    NB: The index will be differentially encoded since the last PrefilledTx in a list
    """
    __slots__ = ("block_index", "tx")

    def __init__(self, block_index: int, tx: Transaction):
        self.block_index = block_index
        self.tx = tx

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED, prev_ind: int = 0):
        """
        We deseriazlied a differentially encoded PrefilledTx. We use prev_ind to denote the previous BLOCK index in
        the corresponding list of prefilled transactions.
        """
        stream = get_stream(byte_stream)

        # Differential index
        diff_ind = read_compact_size(stream)

        # Block index
        block_index = prev_ind + diff_ind + 1

        # tx
        tx = Transaction.from_bytes(stream)

        return cls(block_index, tx)

    def to_bytes(self, prev_ind: int = 0) -> bytes:
        """
        We differentially encoded the block_index to serialize our PrefilledTx. We use prev_ind to denote the
        previous BLOCK index in
        the corresponding list of prefilled transactions.
        """
        # Validate
        if self.block_index < prev_ind:
            raise NetworkDataError("Previous index is greater than object index")
        if self.block_index == prev_ind:
            raise NetworkDataError("Previous index same as object index.")

        # differentially encode the index
        diff_ind = self.block_index - prev_ind - 1

        return write_compact_size(diff_ind) + self.tx.to_bytes()

    def to_dict(self, formatted: bool = True) -> dict:
        return {
            "block_index": write_compact_size(self.block_index).hex() if formatted else self.block_index,
            "tx": self.tx.to_bytes().hex(),
        }


class ShortIDs(Serializable):
    """
    #TODO: Put in serializetion diagram
    Short transaction IDs are used to represent a transaction without sending a full 256-bit hash.
    They are calculated by:
        -single-SHA256 hashing the block header with the nonce appended (in little-endian)
        -Running SipHash-2-4 with the input being the transaction ID and the keys (k0/k1) set to the first two
            little-endian 64-bit (8-byte) integers from the above hash, respectively.
        -Dropping the 2 most significant bytes from the SipHash output to make it 6 bytes.
    """
    __slots__ = ("short_id",)

    def __init__(self, block_header: bytes, nonce: int, txid: bytes):
        # --- Validation --- #
        if len(block_header) != 80:
            raise ValueError(f"block_header must be 80 bytes, got {len(block_header)}")
        if len(txid) != 32:
            raise ValueError(f"txid must be 32 bytes, got {len(txid)}")

        # Step 1: Create the SHA256 hash of the block_header + nonce
        hash_data = block_header + nonce.to_bytes(8, "little")
        hash_value = sha256(hash_data)

        # Step 2: Extract k0 and k1 as the SipHash key (first 16 bytes)
        # SipHash_2_4 expects a 16-byte secret key
        siphash_key = hash_value[:16]

        # Step 3: Run SipHash-2-4 with input being txid and k0/k1
        siphash_result = siphash.SipHash_2_4(siphash_key, txid).hash()

        # Step 4: Create shortId from lower 6 bytes
        self.short_id = siphash_result.to_bytes(8, "little")[:6]

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        """
        Read a short ID directly from bytes (6 bytes)
        Note: This doesn't recalculate, just reads the stored value
        """
        stream = get_stream(byte_stream)
        short_id_bytes = read_stream(stream, 6)

        # Create a dummy instance (we can't recalculate without header/nonce/txid)
        instance = object.__new__(cls)
        instance.short_id = short_id_bytes
        return instance

    def to_bytes(self) -> bytes:
        """Return the 6-byte short ID"""
        return self.short_id

    def to_dict(self, formatted: bool = True) -> dict:
        return {"short_id": self.short_id.hex()}


class HeaderAndShortIDs(Serializable):
    """
    =================================================================
    |   Name            | datatype  | format                | size  |
    =================================================================
    |   header          | bytes     | bytes                 | 80    |
    |   nonce           | int       | little-endian         | 8     |
    |   short_id_num    |           | CompactSize           | 1/3   |
    |   short_ids       | list      | Serialized            | var   |
    |   prefilled_tx_num|           | Compactsize           | 1/3   |
    |   prefilled_txs   | list      | Serialized            | var   |
    =================================================================
    """

    def __init__(self, header: bytes | BlockHeader, nonce: int, short_ids: list[ShortIDs],
                 prefilled_txs: list[PrefilledTx]):
        """
        Args:
            header: Block header (80 bytes)
            nonce: Nonce for short ID generation
            short_ids: List of ShortIDs
            prefilled_txs: List of PrefilledTx objects (with block_index set to actual indices)
        """
        # ---  Validation --- #
        if isinstance(header, bytes) and len(header) != 80:
            raise NetworkDataError("Serialized BlockHeader of incorrect length")

        self.header = header if isinstance(header, bytes) else header.to_bytes()
        self.nonce = nonce
        self.short_ids = short_ids
        self.prefilled_txs = prefilled_txs

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # header
        header = read_stream(stream, 80)

        # nonce
        nonce = read_little_int(stream, 8)

        # short_ids
        short_id_len = read_compact_size(stream)
        short_ids = [ShortIDs.from_bytes(stream) for _ in range(short_id_len)]

        # prefilled_txs - decode with differential encoding
        prefilled_tx_len = read_compact_size(stream)
        prefilled_txs = []
        prev_ind = -1  # Start at -1 since first diff will be added to this

        for _ in range(prefilled_tx_len):
            ptx = PrefilledTx.from_bytes(stream, prev_ind)
            prefilled_txs.append(ptx)
            prev_ind = ptx.block_index

        return cls(header, nonce, short_ids, prefilled_txs)

    def to_bytes(self) -> bytes:
        short_id_len = len(self.short_ids)
        prefilled_tx_len = len(self.prefilled_txs)

        # Serialize header, nonce, and short_ids
        parts = [
            self.header,
            self.nonce.to_bytes(8, "little"),
            write_compact_size(short_id_len),
            b''.join(s.to_bytes() for s in self.short_ids),
            write_compact_size(prefilled_tx_len)
        ]

        # Serialize prefilled_txs with differential encoding
        prev_ind = -1  # Start at -1 since first diff will be subtracted from this
        for ptx in self.prefilled_txs:
            parts.append(ptx.to_bytes(prev_ind))
            prev_ind = ptx.block_index

        return b''.join(parts)

    def to_dict(self, formatted: bool = True):
        short_id_dict = {f'short_id_{x}': self.short_ids[x].to_dict(formatted) for x in range(len(self.short_ids))}

        prefilled_tx_dict = {}
        for i, ptx in enumerate(self.prefilled_txs):
            prefilled_tx_dict[f'prefilled_tx_{i}'] = ptx.to_dict(formatted)

        return {
            "header": self.header.hex(),
            "nonce": self.nonce,
            "short_ids_length": len(self.short_ids),
            "short_ids": short_id_dict,
            "prefilled_txs_length": len(self.prefilled_txs),
            "prefilled_txs": prefilled_tx_dict
        }


class BlockTransactions(Serializable):
    """Provides some requested txs from a block
    =========================================================================
    |   Name        | datatype              | format                | size  |
    =========================================================================
    |   block_hash  |   bytes               |   natural byte order  |   32  |
    |   txs_length  |   int                 |   compactSize         |   var |
    |   txs         |   list[Transactions]  |   tx.to_bytes()       |   var |
    =========================================================================
    """

    def __init__(self, block_hash: bytes, txs: list[Transaction]):
        self.block_hash = block_hash
        self.txs = txs

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # block hash
        block_hash = read_stream(stream, 32)

        # txs
        tx_len = read_compact_size(stream)
        txs = [Transaction.from_bytes(stream) for _ in range(tx_len)]

        return cls(block_hash, txs)

    def to_bytes(self) -> bytes:
        tx_num = len(self.txs)
        tx_parts = [tx.to_bytes() for tx in self.txs]
        return self.block_hash + write_compact_size(tx_num) + b''.join(tx_parts)

    def to_dict(self, formatted: bool = True):
        tx_num = len(self.txs)
        return {
            # Formatted block_hash is reversed for display
            "block_hash": self.block_hash[::-1].hex() if formatted else self.block_hash.hex(),
            "txs_length": write_compact_size(tx_num).hex() if formatted else tx_num,
            "txs": {
                f"tx_{x}": self.txs[x].to_dict(formatted) for x in range(tx_num)
            }
        }


class BlockTransactionsRequest(Serializable):
    """Used to list tx indices in a block being requested
    =========================================================================
    |   Name        | datatype          | format                | size      |
    =========================================================================
    |   block_hash  |   bytes           |   natural byte order  |   32      |
    |   indices_len |   int             |   compactSize         |   1 or 3  |
    |   indices     |   list[int]       |   compactSize*        |  var      |
    =========================================================================
    *indices are differentially encoded
    * We assume indices are given as an ordered list of block tx indices
    """

    def __init__(self, block_hash: bytes, indices: list[int]):
        self.block_hash = block_hash
        self.indices = indices

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # block_hash
        block_hash = read_stream(stream, 32)

        # indices
        indices_len = read_compact_size(stream)
        indices_diff = [read_compact_size(stream) for _ in range(indices_len)]  # differentially encoded

        # decoded indices
        indices = decode_differential(indices_diff)

        return cls(block_hash, indices)

    def to_bytes(self) -> bytes:
        index_num = len(self.indices)

        # Differentially encode the indices as integers
        diff_indices = encode_differential(self.indices)

        # compactSize encoding
        index_parts = [write_compact_size(diff) for diff in diff_indices]
        return self.block_hash + write_compact_size(index_num) + b''.join(index_parts)

    def to_dict(self, formatted: bool = True):
        index_num = len(self.indices)
        formatted_indices = encode_differential(self.indices) if formatted else self.indices

        return {
            "block_hash": self.block_hash[::-1].hex() if formatted else self.block_hash.hex(),
            "index_num": write_compact_size(index_num).hex() if formatted else index_num,
            "indices": formatted_indices
        }


# --- TESTING
if __name__ == "__main__":
    sep = "===" * 40

    print(" --- NETWORK DATA TESTING --- ")
    print(sep)

    # --- BlockTransactions --- #
    # display hash
    known_block_hash = bytes.fromhex("000000000000b0b8b4e8105d62300d63c8ec1a1df0af1c2cdbd943b156a8cd79")[::-1]
    known_tx_bytes1 = bytes.fromhex(
        "010000000199db128ad1e9247b8f9182ff57c45949230ff2e9c3f1dd26e6f1c9799ae563c7000000008b48304502203153950a39db89129739d79655e18e844910fc390df3e757444608d68ab7c802022100d679e030889cb2467451c172f8d63c58e85be633f1acdbf85fab87ed95c9eee9014104d0ed1abeba4ecb8e1cdeb2531e0b9adda7541482b60c86e637af94ec82c3aefa777ea9ea50d5242504d19fa4a0500c072db5e5addee09d6808b57d75dd1dd48bffffffff02008eb462000000001976a9143f6a97f34f8c5f6cc697d9650498f3f27060489a88acc0d8a700000000001976a9143478fffab9d7e8d5ec19199e46dcfcf6c6ecb2cf88ac00000000")
    known_tx_bytes2 = bytes.fromhex(
        "0100000001d38c4935a387c0cd0658bddaf9553cdf743221e248cbc02e360ace70fdee721b010000008b4830450221009fce94f4489c0f412d181780a5131cf2bd8d926c38878bb520047e4498e85292022078cca9f887ff4c143800eca06c3faa970b65e14013abe1bb45d548e9c6e3825a014104d987807bdac7bc5935067fa4704e87b6a45c3451f4a0b939a513d3cddc1177a729a5d62195abb94b0c532f616b5e5f0f4b09c15008f9470bf5a8c91e01d5995fffffffff02c0d8a700000000001976a914795c679389d97af7ee450f1237bd8944d03b4bff88ac80dc6461000000001976a914526a1a0926fb3d9df1f7ab101075553106f8d84e88ac00000000")
    tx1 = Transaction.from_bytes(known_tx_bytes1)
    tx2 = Transaction.from_bytes(known_tx_bytes2)

    test_block_tx = BlockTransactions(known_block_hash, [tx1, tx2])
    print(f"BLOCK TRANSACTION: {test_block_tx.to_json()}")

    # --- BLOCK TX REQUEST--- #
    another_known_block_hash = bytes.fromhex("000000000000001154bd96cd2f7c153eee36d2f61faafdf5564bde0348d890d2")[::-1]
    test_tx_indices = [1, 4, 5]
    test_block_txn_req = BlockTransactionsRequest(another_known_block_hash, test_tx_indices)
    print(sep)
    print(f"BLOCK TX REQUEST: {test_block_txn_req.to_json(False)}")
    print(sep)
