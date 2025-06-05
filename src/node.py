"""
Class file for Node
"""
import ipaddress
import socket
import time
from pathlib import Path

from src.blockchain import Blockchain
from src.crypto import hash256
from src.data import to_little_bytes, write_compact_size
from src.db import DB_PATH
from src.script import script_engine, ScriptValidator


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

    def get_version_header(self, magic_bytes: bytes = MAGICBYTES_MAINNET) -> bytes:
        command_bytes = b'version'.ljust(12, b'\x00')  # Make sure the command is 12 bytes
        size = to_little_bytes(85, 4)
        payload = self.get_version_payload("162.120.69.182")
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
        user_agent = write_compact_size(0)
        last_block = to_little_bytes(0, 4)

        # --- TESTING
        # print("==="*50)
        # print(f"PROTOCOL VERSION: {protocol_version.hex()}")
        # print(f"UNIX TIMESTAMP: {unix_timestamp.hex()}")
        # print(f"LOCAL SERVICES: {local_services.hex()}")
        # print(f"REMOTE SERVICES: {remote_services.hex()}")
        # print(f"REMOTE IP: {remote_ip.hex()}")
        # print(f"REMOTE PORT: {remote_port.hex()}")
        # print(f"LOCAL IP: {local_ip.hex()}")
        # print(f"NONCE: {nonce.hex()}")
        # print(f"USER AGENT: {user_agent.hex()}")
        # print(f"LAST BLOCK: {last_block.hex()}")
        # print("==="*50)

        return (protocol_version + local_services + unix_timestamp + remote_services + remote_ip + remote_port +
                local_services + local_ip + local_port + nonce + user_agent + last_block)

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
    print(f"CURRENT HEIGHT: {node.blockchain.height}")
    vh = node.get_version_header()
    print(f"VERSION HEADER: {vh.hex()}")

    learnmeabitcoin_ip = "162.120.69.182"

    vp = node.get_version_payload(learnmeabitcoin_ip)
    print(f"VERSION PAYLOAD: {vp.hex()}")

    # sock = node.connect_to_node()
    # if sock:
    #     print(f"SUCCESS: {sock}")
    #     sleep(10)
    #     sock.close()
