"""
Class file for Node
"""
import io
import ipaddress
import json
import socket
import time
from datetime import datetime
from pathlib import Path

from src.blockchain import Blockchain
from src.crypto import hash256
from src.data import to_little_bytes, write_compact_size, check_length, from_little_bytes, read_compact_size
from src.db import DB_PATH
from src.script import script_engine, ScriptValidator


def bytes_to_binary_string(b: bytes):
    return bin(int.from_bytes(b, 'big'))[2:].zfill(len(b) * 8)


class Header:
    """
    Header class used for sending message
    """
    pass


class Message:
    """
    Used for handling message transmission between nodes
    """

    def __init__(self,
                 magic_bytes: bytes,
                 command: str,
                 size: int,
                 checksum: bytes,
                 payload: bytes
                 ):
        self.magic_bytes = magic_bytes
        self.command = command

        # Check size
        if len(payload) != size:
            raise ValueError("Size of payload not equal to size value")
        self.size = size

        # Verify payload
        if not self._verify_checksum(payload, checksum):
            raise ValueError("Given payload and checksum do not match")

        self.checksum = checksum
        self.payload = payload

    def _verify_checksum(self, payload: bytes, checksum: bytes) -> bool:
        hashed_payload = hash256(payload)
        return hashed_payload[:4] == checksum

    def from_bytes(cls, byte_stream):
        """
        Deserialize a message
        ---------------------------------------------
        | Name          | Format            | Size  |
        ---------------------------------------------
        | Magic Bytes   | bytes             | 4     |
        | command       | ascii bytes       | 12    |
        | size          | little-endian     | 4     |
        | checksum      | bytes             | 4     |
        | payload       | bytes             | size  |
        ---------------------------------------------
        """
        if not isinstance(byte_stream, (bytes, io.BytesIO)):
            raise ValueError(f"Expected byte data stream, received {type(byte_stream)}")

        stream = io.BytesIO(byte_stream) if isinstance(byte_stream, bytes) else byte_stream

        magic_bytes = stream.read(4)
        check_length(magic_bytes, 4, "magic_bytes")

        command = stream.read(12)
        check_length(command, 12, "command")
        ascii_command = command.decode("ascii").rstrip('\x00')

        size = stream.read(4)
        check_length(size, 4, "size")
        size_int = from_little_bytes(size)

        checksum = stream.read(4)
        check_length(checksum, 4, "checksum")

        payload = stream.read(size_int)
        check_length(payload, size_int, "payload")


class Version:
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
        ---------------------------------------------------------
        | Name              | Format                | Size      |
        --------------------------------------------------------|
        protocol version    | little                | 4         |
        services            | little                | 8         |
        time                | little                | 8         |
        remote services     | little                | 8         |
        remote ip           | ipv6, big             | 16        |
        remote port         | big                   | 2         |
        local services      | little                | 8         |
        local ip            | ipv6, big             | 16        |
        local port          | big                   | 2         |
        nonce               | little                | 8         |
        user agent          | compact size, ascii   | compact   |
        last block          | little                | 4         |
        --------------------------------------------------------|
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


class Node:
    """
    The Node class for BitClone
    """
    # --- PORTS
    MAINNET = 8333
    TESTNET = 18333
    REGTEST = 18444

    # --- MAGIC BYTES
    MAGICBYTES_MAINNET = bytes.fromhex("f9beb4d9")
    MAGICBYTES_TESTNET = bytes.fromhex("0b110907")
    MAGICBYTES_REGTEST = bytes.fromhex("fabfb5da")

    # --- VERACK
    VERACK = bytes.fromhex("F9BEB4D976657261636B000000000000000000005DF6E0E2")

    def __init__(self, db_path: Path = DB_PATH):
        self.blockchain = Blockchain(db_path)
        self.script_engine = script_engine
        self.mempool = []
        self.validator = ScriptValidator(self.blockchain.db)

    def connect_to_node(self, port: int = MAINNET):
        """
        Open a TCP socket connection to a node at the given IP and port.
        """
        node_ip = "162.120.69.182"  # or pass this as an argument

        try:
            # Create a TCP/IP socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Optionally set timeout
            s.settimeout(10)
            # Connect to the node
            s.connect((node_ip, port))
            print(f"Connected to {node_ip}:{port}")
            # You can now use s.send(), s.recv(), etc.
            # Remember to close it when done
            return s  # or store as self.sock for later use

        except Exception as e:
            print(f"Failed to connect to {node_ip}:{port}: {e}")
            return None

    def send_message(self, s: socket.socket, message: bytes):
        s.send(message)

    def receive_message(self, s: socket.socket):
        # Get header
        magic_bytes = s.recv(4)
        command = s.recv(12)
        size = s.recv(4)
        checksum = s.recv(4)

        # Decode
        ascii_command = command.decode("ascii").rstrip('\x00')
        size_int = int.from_bytes(size, "little")

        # Payload
        payload = s.recv(size_int)

        # TESTING
        print(f"===" * 50)
        print(f"RECEIVED MESSAGE FROM {s.getpeername()}")
        print(f"===" * 50)
        print(f"MAGIC BYTES: {magic_bytes.hex()}")
        print(f"DECODED COMMAND: {ascii_command}")
        print(f"MESSAGE SIZE: {size_int}")
        print(f"CHECKSUM: {checksum.hex()}")
        print(f"===" * 50)
        print(f"PAYLOAD: {payload.hex()}")
        print(f"===" * 50, end="\n\n")

    def get_version_header(self, payload: bytes, magic_bytes: bytes = MAGICBYTES_MAINNET) -> bytes:
        command_bytes = b'version'.ljust(12, b'\x00')  # Make sure the command is 12 bytes
        size = to_little_bytes(len(payload), 4)
        checksum = hash256(payload)[:4]
        return magic_bytes + command_bytes + size + checksum

    def get_version_payload(self, remote_ip: str):
        protocol_version = to_little_bytes(70014, 4)

        local_services = to_little_bytes(0, 8)  # Services offered by this node
        unix_timestamp = to_little_bytes(int(time.time()), 8)

        remote_services = to_little_bytes(0, 8)  # Services we think node we are connecting to will offer
        remote_ip = self.address_to_ipv6_bytes(remote_ip)
        remote_port = (8333).to_bytes(2, "big")
        local_ip = self.address_to_ipv6_bytes("127.0.0.1")
        local_port = (8333).to_bytes(2, "big")
        nonce = to_little_bytes(0, 8)
        user_agent = b'Dr. Greg'
        user_agent_size = write_compact_size(len(user_agent))
        last_block = to_little_bytes(0, 4)

        return (protocol_version + local_services + unix_timestamp + remote_services + remote_ip + remote_port +
                local_services + local_ip + local_port + nonce + user_agent_size + user_agent + last_block)

    def address_to_ipv6_bytes(self, address: str) -> bytes:
        """
        Given an IPv4 or IPv6 address string, return the 16-byte IPv6-mapped bytes.
        """
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv4Address):
            # Convert to IPv6-mapped address
            ipv6 = ipaddress.IPv6Address(f"::ffff:{address}")
            return ipv6.packed
        elif isinstance(ip, ipaddress.IPv6Address):
            return ip.packed
        else:
            raise ValueError("Invalid IP address")


# -- TESTING
if __name__ == "__main__":
    node = Node()
    learnmeabitcoin_ip = "162.120.69.182"

    greg_payload = node.get_version_payload(learnmeabitcoin_ip)
    greg_header = node.get_version_header(greg_payload)
    print(f"GREG HEADER: {greg_header.hex()}")
    print(f"GREG PAYLOAD: {greg_payload.hex()}")

    greg_version = Version.from_bytes(greg_payload)
    print(f"GREG VERSION: {greg_version.to_json()}")

    sock = node.connect_to_node()

    if sock:
        print(f"SUCCESS: CONNECTED TO {sock.getpeername()}")
        print(f"SOCKET: {sock}")

        # -- Handshake
        greg_payload = node.get_version_payload(learnmeabitcoin_ip)
        greg_header = node.get_version_header(payload=greg_payload)
        node.send_message(sock, greg_header + greg_payload)

        # Get version
        node.receive_message(sock)

        # Get verack
        node.receive_message(sock)

        # Send verack
        node.send_message(sock, Node.VERACK)

        sock.close()
