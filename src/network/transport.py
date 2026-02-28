"""
Transport owns sockets and message I/O.
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Optional

from src.core import NetworkError
from src.network.datatypes.network_types import PeerState
from src.network.messages.header import Header, ALLOWED_MAGIC
from src.network.messages.message import Message, validate_package
from src.network.peer import Peer


@dataclass
class Connection:
    """Represents a live TCP connection to a peer."""
    sock: socket.socket
    peer_key: tuple[str, int]
    connected_at: float = field(default_factory=time.time)
    last_rx: float = field(default_factory=time.time)
    last_tx: float = field(default_factory=time.time)


class Transport:
    """Manages connections and sending/receiving messages."""

    def __init__(self, timeout: int = 120):
        self._timeout = timeout
        self._conns: dict[tuple[str, int], Connection] = {}
        # If you want strict network-only later, replace this with a single expected magic.
        self._allowed_magic = ALLOWED_MAGIC

    def connect(self, peer: Peer) -> None:
        if peer.key in self._conns:
            return

        peer.state = PeerState.CONNECTING
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)

        try:
            sock.connect((str(peer.host), peer.port))
        except OSError as e:
            sock.close()
            peer.state = PeerState.DISCONNECTED
            peer.fail_count += 1
            peer.last_fail = time.time()
            raise ConnectionError(f"Failed to connect to {peer.host}:{peer.port}: {e}") from e

        self._conns[peer.key] = Connection(sock=sock, peer_key=peer.key)
        peer.state = PeerState.CONNECTED
        peer.last_success = time.time()
        peer.last_seen = time.time()

    def disconnect(self, peer: Peer) -> None:
        conn = self._conns.pop(peer.key, None)
        peer.state = PeerState.DISCONNECTED
        if conn:
            try:
                conn.sock.close()
            except OSError:
                pass

    def send(self, peer: Peer, message: Message) -> None:
        conn = self._require_conn(peer)
        data = message.to_bytes()
        conn.sock.sendall(data)
        conn.last_tx = time.time()
        peer.last_seen = time.time()

    def recv_one(self, peer: Peer, expected_command: Optional[str] = None) -> Message:
        conn = self._require_conn(peer)

        header_bytes = self._recv_exact(conn.sock, 24)
        header = Header.from_bytes(header_bytes)

        # --- Validate magic bytes (container membership must be against a real tuple/list, not a class)
        if header.magic_bytes not in self._allowed_magic:
            raise NetworkError(f"Unknown magic bytes: {header.magic_bytes.hex()}")

        payload_bytes = self._recv_exact(conn.sock, header.size)

        # --- Validate header + payload
        if not validate_package(header, payload_bytes):
            raise NetworkError("Failed to validate header and payload")

        conn.last_rx = time.time()
        peer.last_seen = time.time()

        # Rebuild full message for existing Message.from_bytes() API
        msg_cls = Message.get_registered(header.command)
        return msg_cls.from_bytes(header_bytes + payload_bytes)

    def _require_conn(self, peer: Peer) -> Connection:
        conn = self._conns.get(peer.key)
        if not conn:
            raise ConnectionError(f"Not connected to {peer.host}:{peer.port}")
        return conn

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed while receiving data")
            data += chunk
        return data
