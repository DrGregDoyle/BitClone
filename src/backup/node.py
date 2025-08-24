"""
The Node class
"""

import random
import socket
from pathlib import Path
from time import time as now

from src.backup.blockchain import Blockchain
from src.backup.data import NetAddr, NodeType, Header, Wire
from src.backup.db import DB_PATH
from src.backup.logger import get_logger
from src.backup.network import Message, Version, VerAck

LMAB_IP = "162.120.69.182"
PORT = 8333  # Mainnet

# Formatting
logger = get_logger(__name__, "DEBUG")
divider = "=====" * 25
thin_divider = "-----" * 25


class Node:

    def __init__(self, db_path: Path = DB_PATH, usr_agent: str = "/BitClone: 0.1/"):
        self.blockchain = Blockchain(db_path)
        self.peers = []
        self.usr_agent = usr_agent

    # --- HELPERS --- #

    def _build_version(self, remote_ip: str, remote_port: int) -> Version:
        current_time = int(now())

        # Create remote addr
        remote_addr = NetAddr(
            timestamp=current_time,
            services=NodeType.NONE,
            ip_addr=remote_ip,
            port=remote_port,
            is_version=True
        )

        # Create local addr
        local_addr = NetAddr(
            timestamp=current_time,
            services=NodeType.NONE,
            ip_addr="127.0.0.1",
            port=PORT,
            is_version=True
        )

        version_message = Version(
            version=70014,
            services=NodeType.NONE,
            timestamp=current_time,
            remote_addr=remote_addr,
            local_addr=local_addr,
            nonce=random.getrandbits(64),
            user_agent=self.usr_agent,
            last_block=0
        )
        return version_message

    # --- NETWORKING --- #

    def open_connection(self, host: str, port: int, timeout: float = 10.0) -> socket.socket:
        """
        Open a TCP connection to the given host and port, supporting IPv4 and IPv6.
        Returns the connected socket object.
        """
        addr_info = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        last_error = None
        s = None
        for family, socktype, proto, _, sockaddr in addr_info:
            try:
                s = socket.socket(family, socktype, proto)
                s.settimeout(timeout)
                s.connect(sockaddr)
                return s  # Connected successfully
            except OSError as e:
                last_error = e
                s.close()
                continue

        raise ConnectionError(f"Failed to connect to {host}:{port} - {last_error}")

    # --- RECV

    def recv_exact(self, sock: socket.socket, n: int) -> bytes:
        chunks = []
        remaining = n
        while remaining:
            chunk = sock.recv(remaining)
            if not chunk:
                raise ConnectionError(f"Socket closed while reading {n} bytes")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def recv_header(self, sock: socket.socket):
        header_bytes = self.recv_exact(sock, Wire.Header.TOTAL_LEN)
        temp_header = Header.from_bytes(header_bytes)
        print(f"RECEIVED HEADER: {temp_header.to_json()}")
        return temp_header

    def recv_message(self, sock: socket.socket) -> Message:
        """
        With the socket connected, we get the Header and Payload. Parsing the header command, we return the
        appropriate message
        """
        # Get message data
        header = self.recv_header(sock)
        payload = self.recv_exact(sock, header.size)
        # -- TESTING
        print(f"HEADER SIZE: {header.size}")
        print(f"PAYLOAD: {payload.hex()}")
        print(f"PAYLOAD BYTESIZE: {len(payload)}")

        return self.parse_message(header, payload)

    def parse_message(self, header: Header, payload: bytes) -> Message:
        """
        Given a message Header a payload, we return the corresponding Message object
        """
        cls = Message.get_registered(header.command)
        print(f"RECEIVED REGISTERED CLASS: {cls}")
        if cls is None:
            raise ValueError(f"Unknown message type {header.command}")

        return cls.from_payload(payload)

    # --- HANDSHAKE
    def handshake(self, host: str = LMAB_IP, port: int = PORT):
        """
        Perform the Bitcoin handshake:
          1) Send version
          2) Receive version
          3) Receive verack
          4) Send verack
        Returns True on success, False otherwise.
        """
        # Get version and verack
        version_msg = self._build_version(host, port)
        verack_msg = VerAck()
        sock = None

        # --- TESTING
        print(f"CREATED VERSION PAYLOAD: {version_msg.payload().hex()}")

        # Handshake
        try:
            sock = self.open_connection(host, port)

            # 1) Send our version
            sock.sendall(version_msg.message)
            logger.info(f"Sent Node Version Message: {version_msg.to_json()}")

            # 2) Receive version
            recv_version = self.recv_message(sock)
            if not isinstance(recv_version, Version):
                sock.close()
                return False
            logger.info(f"Received Version Message: {recv_version.to_json()}")

            # 3) Receive verack
            recv_verack = self.recv_message(sock)
            if not isinstance(recv_verack, VerAck):
                sock.close()
                return False
            logger.info(f"Received Verack Message: {recv_verack.to_json()}")

            # 4) Send verack
            sock.sendall(verack_msg.message)
            logger.info(f"Send Node Verack Message: {verack_msg.to_json()}")

        except (OSError, ConnectionError, TimeoutError) as e:
            logger.error(f"Handhaske fails with error: {e}")
            return False

        finally:
            try:
                sock.close()
            except (OSError, socket.error):
                pass

        return True


# --- TESTING
if __name__ == "__main__":
    test_node = Node()
    successful_handshake = test_node.handshake()
    print(f"SUCCESSFUL HANDSHAKE: {successful_handshake}")
