"""
Control Message Classes
"""
from datetime import datetime
from io import BytesIO

from src.data import get_stream, read_little_int, read_stream, read_compact_size, write_compact_size, MAINNET, \
    NetAddr, RejectType, to_little_bytes, BloomType, bytes_to_2byte_binary_string
from src.network.messages import ControlMessage

__all__ = ["Version", "VerAck", "Pong", "Ping", "Addr", "Reject", "GetAddr", "SendHeaders", "FilterLoad",
           "FilterClear", "FeeFilter"]


class Version(ControlMessage):
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
    # --- BYTE SIZES
    PORT_BYTES = 2
    VERSION_BYTES = LAST_BLOCK_BYTES = 4
    SERVICE_BYTES = TIME_BYTES = NONCE_BYTES = 8
    IP_BYTES = 16

    def __init__(self, version: int, services: bytes, timestamp: int, remote_addr: NetAddr, local_addr: NetAddr,
                 nonce: int,
                 user_agent: str,
                 last_block: int,
                 magic_bytes: bytes = MAINNET):
        # Magic Bytes
        super().__init__(magic_bytes)
        self.magic_bytes = magic_bytes

        # Raw Data
        self.protocol_version = version
        self.services = services
        self.timestamp = timestamp
        self.remote_net_addr = remote_addr
        self.local_net_addr = local_addr
        self.nonce = nonce
        self.user_agent = user_agent
        self.last_block = last_block

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MAINNET):
        # Setup stream
        stream = get_stream(byte_stream)

        # Read version, services and timestamp
        version = read_little_int(stream, cls.VERSION_BYTES, "protocol_version")
        services = read_stream(stream, cls.SERVICE_BYTES, "services")
        timestamp = read_little_int(stream, cls.TIME_BYTES, "time")

        # Read in remote and local NetAddr
        remote_netaddr = NetAddr.from_bytes(stream, is_version=True)
        local_netaddr = NetAddr.from_bytes(stream, is_version=True)

        # Read in nonce, user agent and last block
        nonce = read_little_int(stream, cls.NONCE_BYTES, "nonce")
        user_agent_size = read_compact_size(stream, "user_agent_size")
        user_agent = read_stream(stream, user_agent_size, "user_agent").decode("ascii")
        last_block = read_little_int(stream, cls.LAST_BLOCK_BYTES, "last_block")

        return cls(version, services, timestamp, remote_netaddr, local_netaddr, nonce, user_agent, last_block,
                   magic_bytes)

    @property
    def command(self) -> str:
        return "version"

    def payload(self):
        byte_string = b''

        # Protocol version, services, time
        byte_string += self.protocol_version.to_bytes(self.VERSION_BYTES, "little")
        byte_string += self.services[::-1]
        byte_string += self.timestamp.to_bytes(self.TIME_BYTES, "little")

        # Remote and local netaddr
        byte_string += self.remote_net_addr.to_bytes() + self.local_net_addr.to_bytes()

        # Nonce, user agent and last block
        byte_string += self.nonce.to_bytes(self.NONCE_BYTES, "little")
        user_agent = self.user_agent.encode("ascii")
        user_agent_size = write_compact_size(len(user_agent))
        byte_string += user_agent_size + user_agent
        byte_string += self.last_block.to_bytes(self.LAST_BLOCK_BYTES, "little")

        return byte_string

    def _payload_dict(self) -> dict:
        version_dict = {
            "protocol_version": self.protocol_version,
            "services": self.services.hex(),
            "time": datetime.utcfromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            "remote_netaddr": self.remote_net_addr.to_dict(),
            "local_netaddr": self.local_net_addr.to_dict(),
            "nonce": self.nonce,
            "user_agent": self.user_agent,
            "last_block": self.last_block
        }
        return version_dict


class VerAck(ControlMessage):

    @property
    def command(self) -> str:
        return "verack"

    def payload(self):
        return b''


class Ping(ControlMessage):
    """
    -------------------------------------------------
    |   Name    | Data type | format        | size  |
    -------------------------------------------------
    |   Nonce   | int       | little-endian | 8     |
    -------------------------------------------------
    """
    NONCE_BYTES = 8

    def __init__(self, nonce: int, magic_bytes: bytes = MAINNET):
        super().__init__(magic_bytes)
        self.nonce = nonce
        self.magic_bytes = magic_bytes

    @classmethod
    def from_bytes(cls, bytes_stream: bytes | BytesIO, magic_bytes: bytes = MAINNET):
        stream = get_stream(bytes_stream)
        nonce = read_little_int(stream, cls.NONCE_BYTES, "nonce")
        return cls(nonce, magic_bytes)

    @property
    def command(self):
        return "ping"

    def payload(self):
        return self.nonce.to_bytes(self.NONCE_BYTES, "little")

    def _payload_dict(self) -> dict:
        return {"nonce": self.nonce}


class Pong(ControlMessage):
    """
    -------------------------------------------------
    |   Name    | Data type | format        | size  |
    -------------------------------------------------
    |   Nonce   | int       | little-endian | 8     |
    -------------------------------------------------
    """
    NONCE_BYTES = 8

    def __init__(self, nonce: int, magic_bytes: bytes = MAINNET):
        super().__init__(magic_bytes)
        self.nonce = nonce
        self.magic_bytes = magic_bytes

    @classmethod
    def from_bytes(cls, bytes_stream: bytes | BytesIO, magic_bytes: bytes = MAINNET):
        stream = get_stream(bytes_stream)
        nonce = read_little_int(stream, cls.NONCE_BYTES, "nonce")
        return cls(nonce, magic_bytes)

    @property
    def command(self):
        return "pong"

    def payload(self):
        return self.nonce.to_bytes(self.NONCE_BYTES, "little")

    def _payload_dict(self) -> dict:
        return {"nonce": self.nonce}


class Addr(ControlMessage):
    """
    -----------------------------------------------------
    |   Name        | Data type | format        | size  |
    -----------------------------------------------------
    |   Count       |   int     | compact Size  | var   |
    |   addr_list   |   list    | NetAddr       | var   |
    -----------------------------------------------------
    """

    def __init__(self, addr_list: list[NetAddr], magic_bytes: bytes = MAINNET):
        super().__init__()
        self.addr_list = addr_list
        self.count = len(addr_list)

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MAINNET):
        # Get stream
        stream = get_stream(byte_stream)

        # Get count
        count = read_compact_size(stream, "addr_count")

        # Get addrs
        addr_list = []
        for _ in range(count):
            addr_list.append(NetAddr.from_bytes(stream))

        return cls(addr_list, magic_bytes)

    @property
    def command(self) -> str:
        return "addr"

    def payload(self) -> bytes:
        payload = write_compact_size(self.count)
        for a in self.addr_list:
            payload += a.to_bytes()
        return payload

    def _payload_dict(self) -> dict:
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


class Reject(ControlMessage):
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
    DATA_BYTES = 32

    def __init__(self, message: str, ccode: RejectType | int, reason: str, data: bytes = b''):
        super().__init__()
        self.reject_message = message
        self.ccode = RejectType(ccode) if isinstance(ccode, int) else ccode
        self.reason = reason
        self.data = data

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MAINNET):
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

    @property
    def command(self) -> str:
        return "reject"

    def payload(self) -> bytes:
        encoded_message = self.reject_message.encode("ascii")
        encoded_reason = self.reason.encode("ascii")
        payload = write_compact_size(
            len(encoded_message)) + encoded_message + self.ccode.to_byte() + write_compact_size(
            len(encoded_reason)) + encoded_reason + self.data
        return payload

    def _payload_dict(self) -> dict:
        payload_dict = {
            "rejected_message": self.reject_message,
            "ccode": self.ccode.name,
            "reason": self.reason,
            "data": self.data.hex()
        }
        return payload_dict


class GetAddr(ControlMessage):
    """
    The getaddr message requests an addr message from the receiving node, preferably one with lots of IP addresses of
    other receiving nodes. The transmitting node can use those IP addresses to quickly update its database of
    available nodes rather than waiting for unsolicited addr messages to arrive over time.

    There is no payload in a getaddr message.
    """

    @property
    def command(self) -> str:
        return "getaddr"

    def payload(self):
        return b''


class SendHeaders(ControlMessage):
    """
    The sendheaders message tells the receiving peer to send new block announcements using a headers message rather
    than an inv message.

    There is no payload in a sendheaders message
    """

    @property
    def command(self) -> str:
        return "sendheaders"

    def payload(self) -> bytes:
        return b''


class FeeFilter(ControlMessage):
    """
    The feefilter message is a request to the receiving peer to not relay any transaction inv messages to the sending
    peer where the fee rate for the transaction is below the fee rate specified in the feefilter message.

    The payload is always 8 bytes long and it encodes 64 bit integer value (LSB / little endian) of feerate. The
    value represents a minimal fee and is expressed in satoshis per 1000 bytes.
    """
    FEERATE_BYTES = 8

    def __init__(self, feerate: int, magic_bytes: bytes = MAINNET):
        super().__init__(magic_bytes)
        self.feerate = feerate
        self.magic_bytes = magic_bytes

    @property
    def command(self) -> str:
        return "feefilter"

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MAINNET):
        stream = get_stream(byte_stream)

        feerate = read_little_int(stream, cls.FEERATE_BYTES, "feerate")
        return cls(feerate, magic_bytes)

    def payload(self) -> bytes:
        return to_little_bytes(self.feerate, self.FEERATE_BYTES)

    def _payload_dict(self) -> dict:
        return {
            "feerate": self.feerate
        }


class FilterClear(ControlMessage):
    """
    The filterclear message tells the receiving peer to remove a previously-set bloom filter. This also undoes the
    effect of setting the relay field in the version message to 0, allowing unfiltered access to inv messages
    announcing new transactions.

    Bitcoin Core does not require a filterclear message before a replacement filter is loaded with filterload. It also
    doesn’t require a filterload message before a filterclear message.

    There is no payload in a filterclear message
    """

    @property
    def command(self) -> str:
        return "filterclear"

    def payload(self) -> bytes:
        return b''


class FilterLoad(ControlMessage):
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
    MAX_FILTER = 0x8ca0  # 36,000 bytes
    MAX_HASHFUNC = 0x32  # 50
    HASHFUNC_BYTES = TWEAK_BYTES = 4
    FLAG_BYTES = 1

    def __init__(self, filter_bytes: bytes, nhashfunc: int, ntweak: int, nflags: int | BloomType,
                 magic_bytes: bytes = MAINNET):
        super().__init__(magic_bytes)
        # Error checking
        if len(filter_bytes) > self.MAX_FILTER:
            raise ValueError(f"Size of filter bytes exceeds {self.MAX_FILTER}. Filter size: {len(filter_bytes)}")
        if nhashfunc > self.MAX_HASHFUNC:
            raise ValueError(f"Hash function num exceeds {self.MAX_HASHFUNC}. Hashfunc num: {nhashfunc}")

        self.filter_bytes = filter_bytes
        self.filter_bytes_size = len(self.filter_bytes)
        self.nhashfunc = nhashfunc
        self.ntweak = ntweak
        self.nflags = BloomType(nflags) if isinstance(nflags, int) else nflags  # BloomType

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MAINNET):
        # Get Stream
        stream = get_stream(byte_stream)

        # Get filter_bytes
        filter_size = read_compact_size(stream, "filter_bytes_size")
        filter_bytes = read_stream(stream, filter_size, "filter_bytes")

        # Get n-vals
        nhashfunc = read_little_int(stream, cls.HASHFUNC_BYTES, "n_hash_func")
        ntweak = read_little_int(stream, cls.TWEAK_BYTES, "n_tweak")
        nflag = read_little_int(stream, cls.FLAG_BYTES, "n_flags")

        return cls(filter_bytes, nhashfunc, ntweak, nflag)

    def payload(self) -> bytes:
        payload_parts = [write_compact_size(self.filter_bytes_size), self.filter_bytes,
                         to_little_bytes(self.nhashfunc, self.HASHFUNC_BYTES),
                         to_little_bytes(self.ntweak, self.TWEAK_BYTES),
                         self.nflags.to_byte()]
        return b''.join(payload_parts)

    def _payload_dict(self) -> dict:
        payload_dict = {
            "filter_bytes_size": self.filter_bytes_size,
            "filter_bytes": self.filter_bytes.hex(),
            "binary_filter": bytes_to_2byte_binary_string(self.filter_bytes),
            "n_hash_funct": self.nhashfunc,
            "n_tweak": self.ntweak,
            "nflags": self.nflags.name
        }
        return payload_dict

    @property
    def command(self) -> str:
        return "filterload"


if __name__ == "__main__":
    from random import randint
    from secrets import token_bytes
    import ipaddress
    from time import time as now

    test_version_bytes = bytes.fromhex(
        "7E1101000000000000000000C515CF6100000000000000000000000000000000000000000000FFFF2E13894A208D000000000000000000000000000000000000FFFF7F000001208D00000000000000000000000000")
    test_version = Version.from_bytes(test_version_bytes)
    print(f"TEST VERSION: {test_version.to_json()}")

    test_verack = VerAck()
    print(f"VERACK: {test_verack.to_json()}")

    random_ping = Ping(randint(250, 500))
    print(f"RANDOM PING: {random_ping.to_json()}")
    print(f"PONG: = {Pong(random_ping.nonce).to_json()}")


    def random_netaddr() -> NetAddr:
        # Random services
        services = token_bytes(8)

        # Random ip
        ip_addr = str(ipaddress.IPv4Address(randint(0, 2 ** 32 - 1)))

        # Random port
        port = randint(0, 0xffff)

        return NetAddr(int(now()), services, ip_addr, port)


    net_addr_list = [random_netaddr() for _ in range(randint(1, 5))]
    test_addr = Addr(net_addr_list)
    print(f"TEST ADDR: {test_addr.to_json()}")

    # TEST REJECT MESSAGE
    test_reject = Reject("tx", 0x10, "non-mandatory-script-verify-flag (Witness required)",
                         bytes.fromhex("0e3e2357e806b6cdb1f70f5c5e3a3d6a89e1f4c9f7eb45c8e14a7c7c8e4a5e09"))

    print(f"TEST REJECT: {test_reject.to_json()}")
    rj_from_bytes = Reject.from_bytes(test_reject.payload())
    print(f"REJECT FROM BYTES: {rj_from_bytes.to_json()}")

    test_getaddr = GetAddr()
    test_sendheaders = SendHeaders()
    print(f"GET ADDR: {test_getaddr.to_json()}")
    print(f"SEND HEADERS: {test_sendheaders.to_json()}")

    test_feefilter = FeeFilter(50000)
    print(f"FEE FILTER: {test_feefilter.to_json()}")

    test_filterclear = FilterClear()
    print(f"FILTER CLEAR: {test_filterclear.to_json()}")

    # test_filter_bytes = token_bytes(randint(100, 200))
    test_filter_bytes = bytes.fromhex("b50f")
    test_nhashfunc = randint(1, 50)
    # test_ntweak = int.from_bytes(token_bytes(4), "little")
    test_ntweak = 0
    test_nflag = 0  # randint(0, 2)
    test_filterload = FilterLoad(test_filter_bytes, test_nhashfunc, test_ntweak, test_nflag)
    print(f"TEST FILTERLOAD: {test_filterload.to_json()}")
