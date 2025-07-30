"""
The Node class
"""

import socket as _sock
from time import time as now

from src.data import NetAddr, BitcoinFormats, Header, NodeType
from src.logger import get_logger
from src.network.control_messages import *
from src.network.message import Message

LEARN_ME_A_BITCOIN_IP = "162.120.69.182"
BN = BitcoinFormats.Network
MB = BitcoinFormats.MagicBytes

__all__ = ["Node"]
logger = get_logger(__name__)


class Node:
    SOCKET_TIMEOUT = 5

    def __init__(self):
        pass

    def create_version(self, remote_ip: str = LEARN_ME_A_BITCOIN_IP, port: int = 8333,
                       usr_agent: str = "Dr. Greg | BitClone testing") -> Version:
        current_time = int(now())

        # Create remote addr
        remote_addr = NetAddr(
            timestamp=current_time,
            services=NodeType.NONE,
            ip_addr=remote_ip,
            port=port,
            is_version=True
        )

        # Create local addr
        local_addr = NetAddr(
            timestamp=current_time,
            services=NodeType.NONE,
            ip_addr="127.0.0.1",
            port=port,
            is_version=True
        )

        version_message = Version(
            version=0,
            services=NodeType.NONE,
            timestamp=current_time,
            remote_addr=remote_addr,
            local_addr=local_addr,
            nonce=0,
            user_agent=usr_agent,
            last_block=0
        )
        return version_message

    def parse_message(self, message: bytes) -> Message:
        """
        Reads in the header and returns the correct message based on the command
        """
        # Split header and payload
        header_bytes = message[:BN.MESSAGE_HEADER]
        payload_bytes = message[BN.MESSAGE_HEADER:]

        # Parse header
        recovered_header = Header.from_bytes(header_bytes)

        match recovered_header.command:
            case "version":
                return Version.from_bytes(payload_bytes)
            case "verack":
                if payload_bytes > 0:
                    raise ValueError("Verack Message has non-empty payload")
                return VerAck()
            # TODO: Add other message types
            case _:
                pass
                # return None

    def send_message(self, sock: _sock.socket, msg: Message):
        sock.send(msg.message)

    def recv_message(self, sock: _sock.socket):
        # Create header
        header_bytes = sock.recv(BN.MESSAGE_HEADER)
        header = Header.from_bytes(header_bytes)

        # Read payload
        payload = sock.recv(header.size)

    def handshake(self, remote_ip: str = LEARN_ME_A_BITCOIN_IP, port: int = 8333):
        """
        Attempts a handshake with the given remote_ip
        """
        sock = self.open_connection(remote_ip, port)
        if sock:
            # Create version and verack Message objects
            version = self.create_version(remote_ip=remote_ip, port=port, usr_agent="Dr. Greg | BitClone testing")
            verack = VerAck()

            # Send version

    def open_connection(self, remote_ip: str = LEARN_ME_A_BITCOIN_IP, port: int = 8333) -> _sock.socket:
        s = None
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(self.SOCKET_TIMEOUT)
            s.connect((remote_ip, port))
        except (_sock.timeout, OSError) as e:
            logger.debug(f"Connection attempt to {remote_ip}:{port} failed: {e}")
            try:
                s.close()
            except (_sock.timeout, OSError) as f:
                logger.debug(f"Closing socket failed: {f}")
                pass  # ignore errors while closing
        return s

    def close_connection(self, sock: _sock.socket):
        try:
            sock.shutdown(_sock.SHUT_RDWR)  # Disable further sends/receives
        except OSError as exc:
            logger.debug("Socket shutdown error: %s", exc)

        try:
            sock.close()
            logger.debug("Socket closed.")
        except Exception as exc:  # pragma: no cover
            logger.error("Failed to close socket cleanly: %s", exc)


class Messenger:
    """
    A helper class for handling messaging inside the node
    """
