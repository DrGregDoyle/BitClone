"""
Compact Filter messages for P2P networking (BIP 157 / BIP 158)

These are DATA messages — they carry compact filter data used by light clients
to sync without downloading full blocks, without revealing which addresses they
are interested in (unlike the older BIP 37 Bloom filter approach).

Flow:
    getcfcheckpt  →  cfcheckpt       (bootstrap evenly-spaced checkpoints)
    getcfheaders  →  cfheaders       (fill in the filter header chain)
    getcfilters   →  cfilter (×N)    (download filters, scan for matches)
                                      ↓ match found?
                                  getdata → block (fetch only relevant blocks)

Filter type 0x00 = Basic block filter (BIP 158): commits to all input outpoints
and output scripts in a block.
"""

from src.core import NETWORK, SERIALIZED, get_stream, read_compact_size, read_little_int, read_stream
from src.core.byte_stream import write_compact_size
from src.network.messages.message import Message

__all__ = [
    "CFilter",
    "CFHeaders",
    "CFCheckpt",
    "GetCFilters",
    "GetCFHeaders",
    "GetCFCheckpt",
]


# === PARENT CLASSES === #

class GetCFRangeParent(Message):
    """
    Shared parent for GetCFilters and GetCFHeaders.
    Both messages ask for a range of filter data identified by
    (filter_type, start_height, stop_hash).
    =========================================================================
    |   name            |   datatype    |   serialized format   |   size    |
    =========================================================================
    |   filter_type     |   int         |   little-endian       |   1       |
    |   start_height    |   int         |   little-endian       |   4       |
    |   stop_hash       |   bytes       |   internal byte order |   32      |
    =========================================================================
    * stop_hash is the block hash of the last block for which a filter is requested.
    * Nodes will not serve more than 1000 filters per request.
    """

    def __init__(self, filter_type: int, start_height: int, stop_hash: bytes):
        super().__init__()
        self.filter_type = filter_type
        self.start_height = start_height
        self.stop_hash = stop_hash

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # filter_type — 1 byte
        filter_type = read_little_int(stream, NETWORK.FILTER_TYPE_LENGTH)

        # start_height — 4 bytes little-endian
        start_height = read_little_int(stream, NETWORK.FILTER_START_HEIGHT_LENGTH)

        # stop_hash — 32 bytes internal byte order
        stop_hash = read_stream(stream, NETWORK.HASH_LENGTH)

        return cls(filter_type, start_height, stop_hash)

    def to_payload(self) -> bytes:
        return (
                self.filter_type.to_bytes(NETWORK.FILTER_TYPE_LENGTH, "little")
                + self.start_height.to_bytes(NETWORK.FILTER_START_HEIGHT_LENGTH, "little")
                + self.stop_hash
        )

    def payload_dict(self) -> dict:
        return {
            "filter_type": self.filter_type.to_bytes(NETWORK.FILTER_TYPE_LENGTH, "little").hex(),
            "start_height": self.start_height.to_bytes(NETWORK.FILTER_START_HEIGHT_LENGTH, "little").hex(),
            "stop_hash": self.stop_hash.hex(),
        }

    def payload_data(self) -> dict:
        return {
            "filter_type": self.filter_type,
            "start_height": self.start_height,
            "stop_hash": self.stop_hash.hex(),
        }


# === CF MESSAGE CLASSES === #

class GetCFilters(GetCFRangeParent):
    """
    Request compact filters for a range of blocks (BIP 157).
    The receiving node responds with one cfilter message per requested block.
    =========================================================================
    |   name            |   datatype    |   serialized format   |   size    |
    =========================================================================
    |   filter_type     |   int         |   little-endian       |   1       |
    |   start_height    |   int         |   little-endian       |   4       |
    |   stop_hash       |   bytes       |   internal byte order |   32      |
    =========================================================================
    """
    COMMAND = "getcfilters"


class CFilter(Message):
    """
    A single compact filter for a block, sent in response to getcfilters (BIP 157).
    =========================================================================
    |   name            |   datatype    |   serialized format   |   size    |
    =========================================================================
    |   filter_type     |   int         |   little-endian       |   1       |
    |   block_hash      |   bytes       |   internal byte order |   32      |
    |   num_filter_bytes|   int         |   CompactSize         |   var     |
    |   filter_data     |   bytes       |   bytes               |   var     |
    =========================================================================
    * filter_data is a Golomb-Rice coded set (GCS) as defined in BIP 158.
    """
    COMMAND = "cfilter"

    def __init__(self, filter_type: int, block_hash: bytes, filter_data: bytes):
        super().__init__()
        self.filter_type = filter_type
        self.block_hash = block_hash
        self.filter_data = filter_data

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # filter_type — 1 byte
        filter_type = read_little_int(stream, NETWORK.FILTER_TYPE_LENGTH)

        # block_hash — 32 bytes
        block_hash = read_stream(stream, NETWORK.HASH_LENGTH)

        # filter_data — prefixed by CompactSize length
        num_filter_bytes = read_compact_size(stream)
        filter_data = read_stream(stream, num_filter_bytes)

        return cls(filter_type, block_hash, filter_data)

    def to_payload(self) -> bytes:
        return (
                self.filter_type.to_bytes(NETWORK.FILTER_TYPE_LENGTH, "little")
                + self.block_hash
                + write_compact_size(len(self.filter_data))
                + self.filter_data
        )

    def payload_dict(self) -> dict:
        return {
            "filter_type": self.filter_type.to_bytes(NETWORK.FILTER_TYPE_LENGTH, "little").hex(),
            "block_hash": self.block_hash.hex(),
            "num_filter_bytes": write_compact_size(len(self.filter_data)).hex(),
            "filter_data": self.filter_data.hex(),
        }

    def payload_data(self) -> dict:
        return {
            "filter_type": self.filter_type,
            "block_hash": self.block_hash.hex(),
            "num_filter_bytes": len(self.filter_data),
            "filter_data": self.filter_data.hex(),
        }


class GetCFHeaders(GetCFRangeParent):
    """
    Request compact filter headers for a range of blocks (BIP 157).
    Filter headers form a chain (each commits to the previous one) that lets
    the client verify downloaded filters without fetching all filter data.
    The receiving node responds with a single cfheaders message.
    =========================================================================
    |   name            |   datatype    |   serialized format   |   size    |
    =========================================================================
    |   filter_type     |   int         |   little-endian       |   1       |
    |   start_height    |   int         |   little-endian       |   4       |
    |   stop_hash       |   bytes       |   internal byte order |   32      |
    =========================================================================
    """
    COMMAND = "getcfheaders"


class CFHeaders(Message):
    """
    A batch of compact filter headers, sent in response to getcfheaders (BIP 157).
    =====================================================================================
    |   name                    |   datatype    |   serialized format   |   size        |
    =====================================================================================
    |   filter_type             |   int         |   little-endian       |   1           |
    |   stop_hash               |   bytes       |   internal byte order |   32          |
    |   previous_filter_header  |   bytes       |   internal byte order |   32          |
    |   filter_hashes_length    |   int         |   CompactSize         |   var         |
    |   filter_hashes           |   list[bytes] |   internal byte order |   32 each     |
    =====================================================================================
    * previous_filter_header is the filter header preceding start_height, used to
      anchor the chain so the client can verify the returned hashes form a valid chain.
    * filter_hashes are the hash of each individual filter (not the chained header).
      The client derives the filter headers by chaining: hash(prev_header || filter_hash).
    """
    COMMAND = "cfheaders"

    def __init__(
            self,
            filter_type: int,
            stop_hash: bytes,
            previous_filter_header: bytes,
            filter_hashes: list[bytes],
    ):
        super().__init__()
        self.filter_type = filter_type
        self.stop_hash = stop_hash
        self.previous_filter_header = previous_filter_header
        self.filter_hashes = filter_hashes

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # filter_type — 1 byte
        filter_type = read_little_int(stream, NETWORK.FILTER_TYPE_LENGTH)

        # stop_hash — 32 bytes
        stop_hash = read_stream(stream, NETWORK.HASH_LENGTH)

        # previous_filter_header — 32 bytes
        previous_filter_header = read_stream(stream, NETWORK.HASH_LENGTH)

        # filter_hashes — CompactSize count followed by 32-byte hashes
        filter_hashes_length = read_compact_size(stream)
        filter_hashes = [read_stream(stream, NETWORK.HASH_LENGTH) for _ in range(filter_hashes_length)]

        return cls(filter_type, stop_hash, previous_filter_header, filter_hashes)

    def to_payload(self) -> bytes:
        parts = [
            self.filter_type.to_bytes(NETWORK.FILTER_TYPE_LENGTH, "little"),
            self.stop_hash,
            self.previous_filter_header,
            write_compact_size(len(self.filter_hashes)),
            b''.join(self.filter_hashes),
        ]
        return b''.join(parts)

    def payload_dict(self) -> dict:
        count = len(self.filter_hashes)
        return {
            "filter_type": self.filter_type.to_bytes(NETWORK.FILTER_TYPE_LENGTH, "little").hex(),
            "stop_hash": self.stop_hash.hex(),
            "previous_filter_header": self.previous_filter_header.hex(),
            "filter_hashes_length": write_compact_size(count).hex(),
            "filter_hashes": {
                f"filter_hash_{x}": self.filter_hashes[x].hex() for x in range(count)
            },
        }

    def payload_data(self) -> dict:
        count = len(self.filter_hashes)
        return {
            "filter_type": self.filter_type,
            "stop_hash": self.stop_hash.hex(),
            "previous_filter_header": self.previous_filter_header.hex(),
            "filter_hashes_length": count,
            "filter_hashes": {
                f"filter_hash_{x}": self.filter_hashes[x].hex() for x in range(count)
            },
        }


class GetCFCheckpt(Message):
    """
    Request evenly-spaced compact filter header checkpoints (BIP 157).
    Checkpoints are returned every 1000 blocks and let the client bootstrap
    the filter header chain quickly before fetching headers in smaller batches.
    =========================================================================
    |   name            |   datatype    |   serialized format   |   size    |
    =========================================================================
    |   filter_type     |   int         |   little-endian       |   1       |
    |   stop_hash       |   bytes       |   internal byte order |   32      |
    =========================================================================
    """
    COMMAND = "getcfcheckpt"

    def __init__(self, filter_type: int, stop_hash: bytes):
        super().__init__()
        self.filter_type = filter_type
        self.stop_hash = stop_hash

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # filter_type — 1 byte
        filter_type = read_little_int(stream, NETWORK.FILTER_TYPE_LENGTH)

        # stop_hash — 32 bytes
        stop_hash = read_stream(stream, NETWORK.HASH_LENGTH)

        return cls(filter_type, stop_hash)

    def to_payload(self) -> bytes:
        return self.filter_type.to_bytes(NETWORK.FILTER_TYPE_LENGTH, "little") + self.stop_hash

    def payload_dict(self) -> dict:
        return {
            "filter_type": self.filter_type.to_bytes(NETWORK.FILTER_TYPE_LENGTH, "little").hex(),
            "stop_hash": self.stop_hash.hex(),
        }

    def payload_data(self) -> dict:
        return {
            "filter_type": self.filter_type,
            "stop_hash": self.stop_hash.hex(),
        }


class CFCheckpt(Message):
    """
    A list of evenly-spaced filter header checkpoints, sent in response to
    getcfcheckpt (BIP 157). One checkpoint is returned per 1000 blocks up to
    stop_hash, so the client can verify the filter header chain in sections.
    =====================================================================================
    |   name                    |   datatype    |   serialized format   |   size        |
    =====================================================================================
    |   filter_type             |   int         |   little-endian       |   1           |
    |   stop_hash               |   bytes       |   internal byte order |   32          |
    |   filter_headers_length   |   int         |   CompactSize         |   var         |
    |   filter_headers          |   list[bytes] |   internal byte order |   32 each     |
    =====================================================================================
    * filter_headers are the chained filter headers at positions 999, 1999, 2999, …
      (i.e. every 1000th block) up to and including stop_hash.
    """
    COMMAND = "cfcheckpt"

    def __init__(self, filter_type: int, stop_hash: bytes, filter_headers: list[bytes]):
        super().__init__()
        self.filter_type = filter_type
        self.stop_hash = stop_hash
        self.filter_headers = filter_headers

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # filter_type — 1 byte
        filter_type = read_little_int(stream, NETWORK.FILTER_TYPE_LENGTH)

        # stop_hash — 32 bytes
        stop_hash = read_stream(stream, NETWORK.HASH_LENGTH)

        # filter_headers — CompactSize count followed by 32-byte headers
        filter_headers_length = read_compact_size(stream)
        filter_headers = [read_stream(stream, NETWORK.HASH_LENGTH) for _ in range(filter_headers_length)]

        return cls(filter_type, stop_hash, filter_headers)

    def to_payload(self) -> bytes:
        parts = [
            self.filter_type.to_bytes(NETWORK.FILTER_TYPE_LENGTH, "little"),
            self.stop_hash,
            write_compact_size(len(self.filter_headers)),
            b''.join(self.filter_headers),
        ]
        return b''.join(parts)

    def payload_dict(self) -> dict:
        count = len(self.filter_headers)
        return {
            "filter_type": self.filter_type.to_bytes(NETWORK.FILTER_TYPE_LENGTH, "little").hex(),
            "stop_hash": self.stop_hash.hex(),
            "filter_headers_length": write_compact_size(count).hex(),
            "filter_headers": {
                f"filter_header_{x}": self.filter_headers[x].hex() for x in range(count)
            },
        }

    def payload_data(self) -> dict:
        count = len(self.filter_headers)
        return {
            "filter_type": self.filter_type,
            "stop_hash": self.stop_hash.hex(),
            "filter_headers_length": count,
            "filter_headers": {
                f"filter_header_{x}": self.filter_headers[x].hex() for x in range(count)
            },
        }
