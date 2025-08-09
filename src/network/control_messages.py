"""
Control Message Classes

The following network messages all help control the connection between two peers or allow them to advise each other
about the rest of the network:
    -addr
    -feefilter
    -filteradd

    -filterclear
    -filterload
    -getaddr

    -ping
    -pong
    -reject

    -sendheaders
    -verack
    -version
"""
from io import BytesIO

from src.data import get_stream, read_little_int, read_stream, read_compact_size, write_compact_size, \
    NetAddr, RejectType, BloomType, bytes_to_2byte_binary_string, BitcoinFormats, NodeType
from src.network.message import Message

__all__ = ["Addr", "FeeFilter", "FilterAdd", "FilterClear", "FilterLoad", "GetAddr", "Ping", "Pong", "Reject",
           "SendHeaders", "VerAck", "Version"]

BF = BitcoinFormats.Message


# --- PARENT CLASSES FOR SIMILAR MESSAGES --- #

class EmptyMessage(Message):
    """
    Used for Messages with no payload
    """

    def __init__(self):
        super().__init__()

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO = b''):
        return cls()

    @property
    def command(self):
        return self.__class__.command

    def payload(self) -> bytes:
        return b''

    def payload_dict(self) -> dict:
        return {}


class PingPongParent(Message):
    """
    The parent class for the Ping and Pong messages
    """

    def __init__(self, nonce: int):
        super().__init__()
        self.nonce = nonce

    @classmethod
    def from_bytes(cls, bytes_stream: bytes | BytesIO):
        stream = get_stream(bytes_stream)
        nonce = read_little_int(stream, BF.CMPCT_NONCE, "nonce")
        return cls(nonce)

    @property
    def command(self):
        return self.__class__.command

    def payload(self):
        return self.nonce.to_bytes(BF.CMPCT_NONCE, "little")

    def payload_dict(self) -> dict:
        return {"nonce": self.nonce}


# --- CONTROL MESSAGES --- #

class Addr(Message):
    """
    -----------------------------------------------------
    |   Name        | Data type | format        | size  |
    -----------------------------------------------------
    |   Count       |   int     | compact Size  | var   |
    |   addr_list   |   list    | NetAddr       | var   |
    -----------------------------------------------------
    """
    COMMAND = "addr"

    def __init__(self, addr_list: list[NetAddr]):
        super().__init__()
        self.addr_list = addr_list
        self.count = len(addr_list)

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        # Get stream
        stream = get_stream(byte_stream)

        # Get count
        count = read_compact_size(stream, "addr_count")

        # Get addrs
        addr_list = []
        for _ in range(count):
            addr_list.append(NetAddr.from_bytes(stream))

        return cls(addr_list)

    def payload(self) -> bytes:
        payload = write_compact_size(self.count)
        for a in self.addr_list:
            payload += a.to_bytes()
        return payload

    def payload_dict(self) -> dict:
        # Collect addresses first
        addr_dict = {}
        for x in range(self.count):
            temp_addr = self.addr_list[x]
            addr_dict.update({f"net_addr{x}": temp_addr.to_dict()})
        payload_dict = {
            "count": self.count,
            "addr_list": addr_dict
        }
        return payload_dict


class FeeFilter(Message):
    """
    The feefilter message is a request to the receiving peer to not relay any transaction inv messages to the sending
    peer where the fee rate for the transaction is below the fee rate specified in the feefilter message.

    The payload is always 8 bytes long, and it encodes 64-bit integer value (LSB / little endian) of feerate. The
    value represents a minimal fee and is expressed in satoshis per 1000 bytes.
    """
    COMMAND = "feefilter"

    def __init__(self, feerate: int):
        super().__init__()
        self.feerate = feerate

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        stream = get_stream(byte_stream)

        feerate = read_little_int(stream, BF.FEERATE, "feerate")
        return cls(feerate)

    def payload(self) -> bytes:
        return self.feerate.to_bytes(BF.FEERATE, "little")

    def payload_dict(self) -> dict:
        return {
            "feerate": self.payload().hex()
        }


class FilterAdd(Message):
    """
    The filteradd message tells the receiving peer to add a single element to a previously-set bloom filter,
    such as a new public key. The element is sent directly to the receiving peer; the peer then uses the parameters
    set in the filterload message to add the element to the bloom filter.

    Note: a filteradd message will not be accepted unless a filter was previously set with the filterload message.
    """
    COMMAND = "filteradd"

    def __init__(self, element: bytes):
        super().__init__()
        self.element_bytes = len(element)
        self.element = element

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        stream = get_stream(byte_stream)

        # element bytes
        element_bytes = read_compact_size(stream, "element_bytes")

        # element
        element = read_stream(stream, element_bytes, "element")

        return cls(element)

    def payload(self) -> bytes:
        return write_compact_size(self.element_bytes) + self.element

    def payload_dict(self) -> dict:
        return {
            "element_bytes": self.element_bytes,
            "element": self.element.hex()
        }


class FilterClear(Message):
    """
    The filterclear message tells the receiving peer to remove a previously-set bloom filter. This also undoes the
    effect of setting the relay field in the version message to 0, allowing unfiltered access to inv messages
    announcing new transactions.

    Bitcoin Core does not require a filterclear message before a replacement filter is loaded with filterload. It also
    doesn’t require a filterload message before a filterclear message.

    There is no payload in a filterclear message
    """
    COMMAND = "filterclear"

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO = b''):
        return cls()

    def payload(self) -> bytes:
        return b''

    def payload_dict(self) -> dict:
        return {}


class FilterLoad(Message):
    """
    -------------------------------------------------------------------------
    |   Name        |   Data type       |   Byte format     |   byte size   |
    -------------------------------------------------------------------------
    |   filter_size |   int             |   CompactSize     |   varint      |
    |   filter      |   bytes           |   bit_field       |   max 36,000  |
    |   nHashFuncs  |   int (max 50)    |   little-endian   |   4           |
    |   nTweak      |   int             |   little-endian   |   4           |
    |   nFlags      |   BLOOM_TYPE      |   little-endian   |   1           |
    -------------------------------------------------------------------------
    """
    COMMAND = "filterload"

    def __init__(self, filter_bytes: bytes, nhashfunc: int, ntweak: int, nflags: int | BloomType):
        super().__init__()
        # Error checking
        if len(filter_bytes) > BF.MAX_FILTER:
            raise ValueError(f"Size of filter bytes exceeds {BF.MAX_FILTER}. Filter size: {len(filter_bytes)}")
        if nhashfunc > BF.MAX_HASHFUNC:
            raise ValueError(f"Hash function num exceeds {BF.MAX_HASHFUNC}. Hashfunc num: {nhashfunc}")

        self.filter_bytes = filter_bytes
        self.filter_bytes_size = len(self.filter_bytes)
        self.nhashfunc = nhashfunc
        self.ntweak = ntweak
        self.nflags = BloomType(nflags) if isinstance(nflags, int) else nflags  # BloomType

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        # Get Stream
        stream = get_stream(byte_stream)

        # Get filter_bytes
        filter_size = read_compact_size(stream, "filter_bytes_size")
        filter_bytes = read_stream(stream, filter_size, "filter_bytes")

        # Get n-vals
        nhashfunc = read_little_int(stream, BF.HASHFUNC, "n_hash_func")
        ntweak = read_little_int(stream, BF.TWEAK, "n_tweak")
        nflag = read_little_int(stream, BF.FLAG, "n_flags")

        return cls(filter_bytes, nhashfunc, ntweak, nflag)

    def payload(self) -> bytes:
        payload_parts = [write_compact_size(self.filter_bytes_size), self.filter_bytes,
                         self.nhashfunc.to_bytes(BF.HASHFUNC, "little"),
                         self.ntweak.to_bytes(BF.TWEAK, "little"),
                         self.nflags.to_byte()]
        return b''.join(payload_parts)

    def payload_dict(self) -> dict:
        payload_dict = {
            "filter_bytes_size": self.filter_bytes_size,
            "filter_bytes": self.filter_bytes.hex(),
            "binary_filter": bytes_to_2byte_binary_string(self.filter_bytes),
            "n_hash_funct": self.nhashfunc,
            "n_tweak": self.ntweak,
            "nflags": self.nflags.name
        }
        return payload_dict


class GetAddr(EmptyMessage):
    """
    The getaddr message requests an addr message from the receiving node, preferably one with lots of IP addresses of
    other receiving nodes. The transmitting node can use those IP addresses to quickly update its database of
    available nodes rather than waiting for unsolicited addr messages to arrive over time.

    There is no payload in a getaddr message.
    """
    COMMAND = "getaddr"


class Ping(PingPongParent):
    """
    -------------------------------------------------
    |   Name    | Data type | format        | size  |
    -------------------------------------------------
    |   Nonce   | int       | little-endian | 8     |
    -------------------------------------------------
    """
    COMMAND = "ping"


class Pong(PingPongParent):
    """
    -------------------------------------------------
    |   Name    | Data type | format        | size  |
    -------------------------------------------------
    |   Nonce   | int       | little-endian | 8     |
    -------------------------------------------------
    """
    COMMAND = "pong"


class Reject(Message):
    """
    ---------------------------------------------------------------------
    |   Name            |   Data type   |   byte format     |   size    |
    ---------------------------------------------------------------------
    |   Msg_bytes       |   int         |   CompactSize     |   varint  |
    |   Msg             |   str         |   ascii bytes     |   var     |
    |   Code            |   int         |   little-endian   |   1       |
    |   Reason_bytes    |   int         |   CompactSize     |   varint  |
    |   Reason          |   str         |   ascii bytes     |   var     |
    |   Data            |   bytes       |   various         |   var     |
    ---------------------------------------------------------------------
    """
    COMMAND = "reject"

    def __init__(self, message: str, ccode: RejectType | int, reason: str, data: bytes = b''):
        super().__init__()
        self.reject_message = message
        self.ccode = RejectType(ccode) if isinstance(ccode, int) else ccode
        self.reason = reason
        self.data = data

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        # Get stream
        stream = get_stream(byte_stream)

        # Read message
        message_len = read_compact_size(stream, "reject_message_length")
        encoded_message = read_stream(stream, message_len, "reject_message")
        message = encoded_message.decode("ascii")

        # Read reject type
        ccode = read_little_int(stream, 1, "ccode")

        # Read reason
        reason_len = read_compact_size(stream, "reason_length")
        encoded_reason = read_stream(stream, reason_len, "reason")
        reason = encoded_reason.decode("ascii")

        # Read data, if any
        data = stream.read()

        return cls(message, ccode, reason, data)

    def payload(self) -> bytes:
        encoded_message = self.reject_message.encode("ascii")
        encoded_reason = self.reason.encode("ascii")
        payload = write_compact_size(
            len(encoded_message)) + encoded_message + self.ccode.to_byte() + write_compact_size(
            len(encoded_reason)) + encoded_reason + self.data
        return payload

    def payload_dict(self) -> dict:
        payload_dict = {
            "rejected_message": self.reject_message,
            "ccode": self.ccode.name,
            "reason": self.reason,
            "data": self.data.hex()
        }
        return payload_dict


class SendHeaders(EmptyMessage):
    """
    The sendheaders message tells the receiving peer to send new block announcements using a headers message rather
    than an inv message.

    There is no payload in a sendheaders message
    """
    COMMAND = "sendheaders"


class VerAck(EmptyMessage):
    COMMAND = "verack"


class Version(Message):
    """
    -----------------------------------------------------------------
    |   Name            | Data type | Formatted         | Size      |
    -----------------------------------------------------------------
    |   (Protocol) version  | int   | little-endian     | 4         |
    |   Services            | bytes | little-endian     | 8         |
    |   Time                | int   | little-endian     | 8         |
    |   Remote services     | bytes | little-endian     | 8         |
    |   Remote ip           | str   | ipv6, big-endian  | 16        |
    |   Remote port         | int   | big-endian        | 2         |
    |   Local services      | bytes | little-endian     | 8         |
    |   Local ip            | str   | ipv6, big-endian  | 16        |
    |   Local port          | int   | big-endian        | 2         |
    |   nonce               | int   | little-endian     | 8         |
    |   user agent size     | *     | compact_size      | varint    |
    |   user agent          | str   | ascii bytes       | varint    |
    |   last block          | int   | little-endian     | 4         |
    -----------------------------------------------------------------
    """
    COMMAND = "version"

    def __init__(self, version: int, services: int | NodeType, timestamp: int, remote_addr: NetAddr,
                 local_addr: NetAddr, nonce: int, user_agent: str, last_block: int):
        # Magic Bytes
        super().__init__()

        # Raw Data
        self.protocol_version = version
        self.services = NodeType(services) if isinstance(services, int) else services
        self.timestamp = timestamp
        self.remote_net_addr = remote_addr
        self.local_net_addr = local_addr
        self.nonce = nonce
        self.user_agent = user_agent
        self.last_block = last_block

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        # Setup stream
        stream = get_stream(byte_stream)

        # Read version, services and timestamp
        version = read_little_int(stream, BF.PROTOCOL_VERSION, "protocol_version")
        services = read_little_int(stream, BF.SERVICES, "services")
        timestamp = read_little_int(stream, BF.TIME, "time")

        # Read in remote and local NetAddr
        remote_netaddr = NetAddr.from_bytes(stream, is_version=True)
        local_netaddr = NetAddr.from_bytes(stream, is_version=True)

        # Read in nonce, user agent and last block
        nonce = read_little_int(stream, BF.CMPCT_NONCE, "nonce")
        user_agent_size = read_compact_size(stream, "user_agent_size")
        user_agent = read_stream(stream, user_agent_size, "user_agent").rstrip(b'\x00').decode("ascii")
        last_block = read_little_int(stream, BF.LASTBLOCK, "last_block")

        return cls(version, services, timestamp, remote_netaddr, local_netaddr, nonce, user_agent, last_block)

    def payload(self):
        byte_string = b''

        # Protocol version, services, time
        byte_string += self.protocol_version.to_bytes(BF.PROTOCOL_VERSION, "little")
        byte_string += self.services.byte_format()
        byte_string += self.timestamp.to_bytes(BF.TIME, "little")

        # Remote and local netaddr
        byte_string += self.remote_net_addr.to_bytes() + self.local_net_addr.to_bytes()

        # Nonce, user agent and last block
        byte_string += self.nonce.to_bytes(BF.CMPCT_NONCE, "little")
        user_agent = self.user_agent.encode("ascii")
        user_agent_size = write_compact_size(len(user_agent))
        byte_string += user_agent_size + user_agent
        byte_string += self.last_block.to_bytes(BF.LASTBLOCK, "little")

        return byte_string

    def payload_dict(self) -> dict:
        version_dict = {
            "protocol_version": self.protocol_version,
            "services": self.services.name,
            "time": self.timestamp,
            # "time": datetime.utcfromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            "remote_netaddr": self.remote_net_addr.to_dict(),
            "local_netaddr": self.local_net_addr.to_dict(),
            "nonce": self.nonce,
            "user_agent": self.user_agent,
            "last_block": self.last_block
        }
        return version_dict
