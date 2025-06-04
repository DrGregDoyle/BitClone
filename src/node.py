"""
Class file for Node
"""
import socket
import time
from pathlib import Path

from src.blockchain import Blockchain
from src.data import to_little_bytes
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
        checksum = b''.ljust(4, b'\x00')  # TODO: Add checksum once payload function is working
        return magic_bytes + command_bytes + size + checksum

    def get_version_payload(self):
        protocol_version = to_little_bytes(70014, 4)
        print(f"PROTOCOL VERSION: {protocol_version.hex()}")

        services = to_little_bytes(0, 8)  # Services offered by this node
        unix_timestamp = int(time.time())
        print(f"UNIX TIMESTAMP: {unix_timestamp}")

        remote_services = to_little_bytes(0, 8)  # Services we think node we are connecting to will offer

        remote_ip = 0


# -- TESTING
if __name__ == "__main__":
    node = Node()
    print(f"CURRENT HEIGHT: {node.blockchain.height}")
    vh = node.get_version_header()
    print(f"VERSION HEADER: {vh.hex()}")

    node.get_version_payload()

    # sock = node.connect_to_node()
    # if sock:
    #     print(f"SUCCESS: {sock}")
    #     sleep(10)
    #     sock.close()
