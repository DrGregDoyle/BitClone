"""
Class file for Node
"""
import ipaddress
import socket
import time
from pathlib import Path

from src.blockchain import Blockchain
from src.data import to_little_bytes, write_compact_size
from src.db import DB_PATH
from src.network import Header, decode_message, Version
from src.script import script_engine, ScriptValidator


# class Header:
#     """
#     Header class used for sending message
#     """
#     pass
#
#
# class Message:
#     """
#     Used for handling message transmission between nodes
#     """
#
#     def __init__(self,
#                  magic_bytes: bytes,
#                  command: str,
#                  size: int,
#                  checksum: bytes,
#                  payload: bytes
#                  ):
#         self.magic_bytes = magic_bytes
#         self.command = command
#
#         # Check size
#         if len(payload) != size:
#             raise ValueError("Size of payload not equal to size value")
#         self.size = size
#
#         # Verify payload
#         if not self._verify_checksum(payload, checksum):
#             raise ValueError("Given payload and checksum do not match")
#
#         self.checksum = checksum
#         self.payload = payload
#
#     def _verify_checksum(self, payload: bytes, checksum: bytes) -> bool:
#         hashed_payload = hash256(payload)
#         return hashed_payload[:4] == checksum
#
#     def from_bytes(cls, byte_stream):
#         """
#         Deserialize a message
#         ---------------------------------------------
#         | Name          | Format            | Size  |
#         ---------------------------------------------
#         | Magic Bytes   | bytes             | 4     |
#         | command       | ascii bytes       | 12    |
#         | size          | little-endian     | 4     |
#         | checksum      | bytes             | 4     |
#         | payload       | bytes             | size  |
#         ---------------------------------------------
#         """
#         if not isinstance(byte_stream, (bytes, io.BytesIO)):
#             raise ValueError(f"Expected byte data stream, received {type(byte_stream)}")
#
#         stream = io.BytesIO(byte_stream) if isinstance(byte_stream, bytes) else byte_stream
#
#         magic_bytes = stream.read(4)
#         check_length(magic_bytes, 4, "magic_bytes")
#
#         command = stream.read(12)
#         check_length(command, 12, "command")
#         ascii_command = command.decode("ascii").rstrip('\x00')
#
#         size = stream.read(4)
#         check_length(size, 4, "size")
#         size_int = from_little_bytes(size)
#
#         checksum = stream.read(4)
#         check_length(checksum, 4, "checksum")
#
#         payload = stream.read(size_int)
#         check_length(payload, size_int, "payload")


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

        raw_msg = magic_bytes + command + size + checksum + payload
        return decode_message(raw_msg)

    def get_version_header(self, payload: bytes, magic_bytes: bytes = MAGICBYTES_MAINNET) -> Header:
        version_header = Header.from_payload(payload, command="version", magic_bytes=magic_bytes)
        return version_header

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
    print(f"GREG HEADER: {greg_header.to_json()}")
    print(f"GREG PAYLOAD: {greg_payload.hex()}")

    greg_version = greg_header.to_bytes() + greg_payload
    print(f"GREG VERSION: {(Version.from_bytes(greg_payload)).to_json()}")

    sock = node.connect_to_node()

    if sock:
        print(f"SUCCESS: CONNECTED TO {sock.getpeername()}")
        print(f"SOCKET: {sock}")

        # -- Handshake
        node.send_message(sock, greg_header.to_bytes() + greg_payload)

        # Get version
        vh, vp = node.receive_message(sock)

        # Get verack
        vah, vap = node.receive_message(sock)

        # Send verack
        node.send_message(sock, Node.VERACK)

        sock.close()

        print("=== LEARN ME A BITCOIN INFO ===")
        print("===" * 80)
        print(f"VERSION HEADER: {(vh.to_json())}")
        print(f"VERSION PAYLOAD: {vp.to_json()}")
        print(f"VERACK HEADER: {vah.to_json()}")
        print(f"VERACK PAYLOAD: {vap}")
        print("===" * 80)
