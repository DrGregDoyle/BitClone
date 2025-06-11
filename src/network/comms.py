"""
The class file for communication between Bitcoin nodes
"""
import io
import ipaddress
import json
from datetime import datetime
from typing import Any

from src.block import Block
from src.crypto import hash256
from src.data import check_length, Serializable, from_little_bytes, bytes_to_binary_string, read_compact_size, \
    to_little_bytes, write_compact_size
from src.tx import Transaction


class Header(Serializable):
    """
    Header class used for sending messages in BitClone
    -------------------------------------
    |   Name    | Format    | Byte size |
    -------------------------------------
    |   Magic Bytes | bytes         | 4 |
    | command       | ascii bytes   | 12|
    | size          | little-endian | 4 |
    | checksum      | bytes         | 4 |
    -------------------------------------
    """
    # --- MAGIC BYTES
    MAINNET_MB = bytes.fromhex("f9beb4d9")
    TESTNET_MB = bytes.fromhex("0b110907")
    REGTEST_MB = bytes.fromhex("fabfb5da")

    def __init__(self, magic_bytes: bytes, command: str, size: int, checksum: bytes):
        self.magic_bytes = magic_bytes
        self.command = command
        self.size = size
        self.checksum = checksum

    @classmethod
    def from_bytes(cls, byte_stream: bytes | io.BytesIO):
        """
        Deserialize header
        -----------------------------------------
        |   Name        |   Format      | Size  |
        -----------------------------------------
        |   Magic Bytes | bytes         | 4     |
        |   Command     | ascii bytes   | 12    |
        |   Size        | little-endian | 4     |
        |   Checksum    | bytes         | 4     |
        -----------------------------------------
        """
        # Setup stream
        if not isinstance(byte_stream, (bytes, io.BytesIO)):
            raise ValueError(f"Expected byte data stream, received {type(byte_stream)}")

        stream = io.BytesIO(byte_stream) if isinstance(byte_stream, bytes) else byte_stream

        # magic_bytes
        magic_bytes = stream.read(4)
        check_length(magic_bytes, 4, "magic_bytes")

        # command
        command_bytes = stream.read(12)
        check_length(command_bytes, 12, "command")
        command = command_bytes.decode("ascii").rstrip("\x00")

        # size
        size_bytes = stream.read(4)
        check_length(size_bytes, 4, "size")
        size = int.from_bytes(size_bytes, "little")

        # checksum
        checksum = stream.read(4)
        check_length(checksum, 4, "checksum")

        return cls(magic_bytes, command, size, checksum)

    @classmethod
    def from_payload(cls, payload: bytes, command: str = "version", magic_bytes: bytes = MAINNET_MB):
        size = len(payload)
        checksum = hash256(payload)[:4]
        return cls(magic_bytes, command, size, checksum)

    def to_bytes(self):
        # Encode command as ASCII and pad/truncate to 12 bytes
        command_bytes = self.command.encode("ascii").ljust(12, b'\x00')[:12]
        return self.magic_bytes + command_bytes + self.size.to_bytes(4, "little") + self.checksum

    def to_dict(self):
        header_dict = {
            "magic_bytes": self.magic_bytes.hex(),
            "command": self.command,
            "size": self.size,
            "checksum": self.checksum.hex()
        }
        return header_dict

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)

    def verify_payload(self, payload: bytes) -> bool:
        """
        Verifies the first 4 bytes of the hash256 of the payload agree with the checksum
        """
        return hash256(payload)[:4] == self.checksum


class Version(Serializable):
    """
    Display class for version message
    """

    def __init__(self,
                 protocol_version: int,
                 services: bytes,
                 timestamp: int,
                 remote_services: bytes,
                 remote_ip: str | ipaddress.IPv6Address | ipaddress.IPv4Address,
                 remote_port: int,
                 local_services: bytes,
                 local_ip: str | ipaddress.IPv6Address | ipaddress.IPv4Address,
                 local_port: int,
                 nonce: int,
                 user_agent: str,
                 last_block: int
                 ):
        self.protocol_version = protocol_version
        self.services = services
        self.timestamp = timestamp
        self.remote_services = remote_services
        self.remote_ip = self._get_ip(remote_ip)
        self.remote_port = remote_port
        self.local_services = local_services
        self.local_ip = self._get_ip(local_ip)
        self.local_port = local_port
        self.nonce = nonce
        self.user_agent = user_agent
        self.last_block = last_block

    def _get_ip(self, unknown_format_ip):
        # Accept str or ipaddress types
        if isinstance(unknown_format_ip, str):
            return ipaddress.IPv6Address(unknown_format_ip)
        elif isinstance(unknown_format_ip, (ipaddress.IPv6Address, ipaddress.IPv4Address)):
            # Converts IPv4 to IPv6-mapped, leaves IPv6 as-is
            return ipaddress.IPv6Address(unknown_format_ip)
        else:
            raise ValueError(f"Unknown format for given ip address: {unknown_format_ip}")

    @classmethod
    def from_bytes(cls, byte_stream):
        """
        Deserialize a version payload
        -----------------------------------------------------------
        | Name                |  Format                | Size     |
        -----------------------------------------------------------
        | protocol version    | little                | 4         |
        | services            | little                | 8         |
        | time                | little                | 8         |
        | remote services     | little                | 8         |
        | remote ip           | ipv6, big             | 16        |
        | remote port         | big                   | 2         |
        | local services      | little                | 8         |
        | local ip            | ipv6, big             | 16        |
        | local port          | big                   | 2         |
        | nonce               | little                | 8         |
        | user agent          | compact size, ascii   | compact   |
        | last block          | little                | 4         |
        -----------------------------------------------------------
        """
        if not isinstance(byte_stream, (bytes, io.BytesIO)):
            raise ValueError(f"Expected byte data stream, received {type(byte_stream)}")

        stream = io.BytesIO(byte_stream) if isinstance(byte_stream, bytes) else byte_stream

        # Helpers
        def read_little_int(stream_size: int, data_type: str):
            byte_read = stream.read(stream_size)
            check_length(byte_read, stream_size, data_type)
            return from_little_bytes(byte_read)

        def read_big_int(stream_size: int, data_type: str):
            byte_read = stream.read(stream_size)
            check_length(byte_read, stream_size, data_type)
            return int.from_bytes(byte_read, "big")

        def read_little_bytes(stream_size: int, data_type: str):
            byte_read = stream.read(stream_size)
            check_length(byte_read, stream_size, data_type)
            return byte_read[::-1]  # Big-endian

        def read_ip(data_type: str):
            ip_bytes = stream.read(16)
            check_length(ip_bytes, 16, data_type)
            return ipaddress.IPv6Address(ip_bytes)

        def read_ascii(stream_size: int):
            ua_bytes = stream.read(stream_size)
            check_length(ua_bytes, stream_size, "user_agent")
            return ua_bytes.decode("ascii")

        protocol_version = read_little_int(4, "protocol_version")
        services = read_little_bytes(8, "services")
        timestamp = read_little_int(8, "unix_timestamp")
        remote_services = read_little_bytes(8, "remote_services")
        remote_ip = read_ip("remote_ip")
        remote_port = read_big_int(2, "remote_port")
        local_services = read_little_bytes(8, "local_services")
        local_ip = read_ip("local_ip")
        local_port = read_big_int(2, "local_port")
        nonce = read_little_int(8, "nonce")
        user_agent_size = read_compact_size(stream)
        user_agent = read_ascii(user_agent_size)
        last_block = read_little_int(4, "last_block")

        return cls(protocol_version, services, timestamp, remote_services, remote_ip, remote_port, local_services,
                   local_ip, local_port, nonce, user_agent, last_block)

    def to_bytes(self):
        # Helper: Ensure services are 8 bytes little-endian
        def to_8bytes_le(val):
            return val if isinstance(val, bytes) and len(val) == 8 else to_little_bytes(val, 8)

        # Protocol version
        b = to_little_bytes(self.protocol_version, 4)
        # Services
        b += to_8bytes_le(self.services)
        # Timestamp (seconds since epoch)
        b += to_little_bytes(self.timestamp, 8)
        # Remote node's services
        b += to_8bytes_le(self.remote_services)
        # Remote node's IP (16 bytes, big-endian)
        b += self.remote_ip.packed
        # Remote node's port (2 bytes, big-endian)
        b += self.remote_port.to_bytes(2, "big")
        # Local services
        b += to_8bytes_le(self.local_services)
        # Local IP (16 bytes, big-endian)
        b += self.local_ip.packed
        # Local port (2 bytes, big-endian)
        b += self.local_port.to_bytes(2, "big")
        # Nonce (8 bytes, little-endian)
        b += to_little_bytes(self.nonce, 8)
        # User agent: CompactSize-prefixed
        user_agent_bytes = self.user_agent.encode("ascii")
        b += write_compact_size(len(user_agent_bytes)) + user_agent_bytes
        # Last block seen (4 bytes, little-endian)
        b += to_little_bytes(self.last_block, 4)
        return b

    def to_dict(self):
        def ip_display(ipv6):
            # If it's IPv4-mapped, return the IPv4 string, else the IPv6 string
            if ipv6.ipv4_mapped:
                return str(ipv6.ipv4_mapped)
            else:
                return str(ipv6)

        version_dict = {
            "protocol_version": self.protocol_version,
            "services": bytes_to_binary_string(self.services),
            "time": datetime.fromtimestamp(self.timestamp).isoformat(),
            "remote_services": bytes_to_binary_string(self.remote_services),
            "remote_ip": ip_display(self.remote_ip),
            "remote_port": self.remote_port,
            "local_services": bytes_to_binary_string(self.local_services),
            "local_ip": ip_display(self.local_ip),
            "local_port": self.local_port,
            "nonce": self.nonce,
            "user_agent": self.user_agent,
            "last_block": self.last_block
        }
        return version_dict

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


def decode_message(message: bytes) -> tuple[Header, Any]:
    """
    We decode the message based on the fixed header size of 24 bytes
    """
    # Parse message
    header_bytes = message[:24]
    payload = message[24:]

    # Get header
    header = Header.from_bytes(header_bytes)

    # Handle payload based on header command
    if header.command == "version":
        return header, Version.from_bytes(payload)
    elif header.command == "verack":
        if payload:
            print(f"VERACK PAYLOAD: {payload.hex()}")
        return header, None
    elif header.command == "tx":
        return header, Transaction.from_bytes(payload)
    elif header.command == "block":
        try:
            test_block = Block.from_bytes(payload)
        except Exception:
            print(f"PAYLOAD: {payload.hex()}")
            raise ValueError("Block from bytes failed for payload")
        return header, test_block
    else:
        print(f"OTHER COMMANDS NOT HANDLED")
        return header, payload


# --- TESTING
if __name__ == "__main__":
    # test_header_bytes = bytes.fromhex("F9BEB4D976657273696F6E0000000000550000002C2F86F3")
    # test_payload_bytes = bytes.fromhex(
    #     "7E1101000000000000000000C515CF6100000000000000000000000000000000000000000000FFFF2E13894A208D000000000000000000000000000000000000FFFF7F000001208D00000000000000000000000000")
    # _header = Header.from_bytes(test_header_bytes)
    # print(_header.to_json())
    # print(f"PAYLOAD PASSES CHECKSUM: {_header.verify_payload(test_payload_bytes)}")
    #
    # _fp_header = Header.from_payload(test_payload_bytes)
    # print(f"FROM PAYLOAD HEDER: {_fp_header.to_json()}")
    #
    # _tobytesfrom_header = Header.from_bytes(_header.to_bytes())
    # print(f"FROM BYTES TO BYTES HEADER: {_tobytesfrom_header.to_json()}")
    #
    # lmab_version = bytes.fromhex(
    #     "80110100090c000000000000bba2456800000000000000000000000000000000000000000000ffffc654ed0ac99f090c0000000000000000000000000000000000000000000000006aa695794768844e102f5361746f7368693a32382e302e302ffcbc0d0001")
    #
    # test_version = Version.from_bytes(lmab_version)
    # print(f"LEARN ME A BITCOIN VERSION: {test_version.to_json()}")
    #
    # lmab_message = bytes.fromhex(
    #     "F9BEB4D976657273696F6E0000000000550000002C2F86F37E1101000000000000000000C515CF6100000000000000000000000000000000000000000000FFFF2E13894A208D000000000000000000000000000000000000FFFF7F000001208D00000000000000000000000000")
    # h1, p1 = decode_message(lmab_message)
    # print(f"LMAB FINAL VERSION -- HEADER: {h1.to_json()}")
    # print(f"LMAB FINAL VERSION -- VERSION: {p1.to_json()}")
    #
    # test_verack = bytes.fromhex("F9BEB4D976657261636B000000000000000000005DF6E0E2")
    # h2, p2 = decode_message(test_verack)
    # print(f"VERACK HEADER: {h2.to_json()}")
    # print(f"VERACK PAYLOAD: {p2.hex()}")
    #
    # test_tx_message = bytes.fromhex(
    #     "f9beb4d9747800000000000000000000e00000006a86deb701000000015ac5ae0a2ba96622c9b79de2c339084c8b1d30f63bb55a315f354db4d9a6abcf010000006b4830450221009ad52459e1e8bd5e758399cc0be963c75726c5089499465d9aa79ffb304ecd3802207d73ea58047f4d1f857b400cbff725ef562b7ada1c26e763c5a1aa6d29d2fdf401210234b7b614fcc0e4d926747d491992d8cc133f076bd79095eddf60c34b0e3fef4affffffff02390205000000000017a914ea3b6d7e92e05370bc8a61d3f05dbfdc90bb1d9587d1df3000000000001976a91425f0800454530549ed93747a6449aefe2618203988ac00000000")
    # h3, p3 = decode_message(test_tx_message)
    # print(f"TX HEADER: {h3.to_json()}")
    # print(f"TX PAYLOAD: {p3.to_json()}")

    test_block_message = bytes.fromhex(
        "f9beb4d9626c6f636b000000000000001d010000e320b6c20100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000")
    h4, p4 = decode_message(test_block_message)
    print(f"BLOCK HEADER: {h4.to_json()}")
    print(f"BLOCK PAYLOAD: {p4.to_json()}")
