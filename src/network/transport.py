"""
Transport owns sockets and message I/O.
"""
from __future__ import annotations

import socket
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from src.core import MAGICBYTES, NETWORK, NetworkError, get_logger
from src.network.datatypes.network_types import PeerState
from src.network.messages.header import Header
from src.network.messages.message import Message, UnknownMessage, validate_package
from src.network.peer import Peer

logger = get_logger(__name__)

AddressInfo = tuple[int, int, int, str, tuple[Any, ...]]
AddressResolver = Callable[[str, int], Iterable[AddressInfo]]
SocketFactory = Callable[[int, int, int], socket.socket]


def _system_resolver(host: str, port: int) -> Iterable[AddressInfo]:
    return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)


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

    def __init__(
            self,
            timeout: int = 120,
            magic_bytes: bytes = MAGICBYTES.MAINNET,
            resolver: AddressResolver | None = None,
            socket_factory: SocketFactory | None = None,
    ):
        self._timeout = timeout
        self._conns: dict[tuple[str, int], Connection] = {}
        self.magic_bytes = magic_bytes
        self._resolver = _system_resolver if resolver is None else resolver
        self._socket_factory = socket_factory

    def connect(self, peer: Peer) -> None:
        if peer.key in self._conns:
            return

        peer.transition(PeerState.CONNECTING)
        last_error: OSError | None = None
        try:
            for family, socktype, protocol, _canonical_name, socket_address in self._resolver(
                    str(peer.host), peer.port
            ):
                sock = self._create_socket(family, socktype, protocol)
                sock.settimeout(self._timeout)
                try:
                    sock.connect(socket_address)
                except OSError as error:
                    last_error = error
                    sock.close()
                    continue
                self._conns[peer.key] = Connection(sock=sock, peer_key=peer.key)
                break
        except OSError as error:
            last_error = error

        if peer.key not in self._conns:
            detail = last_error or OSError("address resolution returned no endpoints")
            peer.transition(PeerState.DISCONNECTED)
            raise ConnectionError(f"Failed to connect to {peer.host}:{peer.port}: {detail}") from detail

        peer.transition(PeerState.CONNECTED, time.time())

    def _create_socket(self, family: int, socktype: int, protocol: int) -> socket.socket:
        if self._socket_factory is not None:
            return self._socket_factory(family, socktype, protocol)
        return socket.socket(family, socktype, protocol)

    def disconnect(self, peer: Peer) -> None:
        conn = self._conns.pop(peer.key, None)
        peer.transition(PeerState.DISCONNECTED)
        if conn:
            try:
                conn.sock.close()
            except OSError:
                pass

    def send(self, peer: Peer, message: Message) -> None:
        conn = self._require_conn(peer)
        message.magic_bytes = self.magic_bytes
        data = message.to_bytes()
        conn.sock.sendall(data)
        conn.last_tx = time.time()
        peer.note_activity()

    def get_local_address(self, peer: Peer) -> tuple[str, int]:
        """Return the local endpoint used by an established peer connection."""
        conn = self._require_conn(peer)
        host, port = conn.sock.getsockname()[:2]
        return str(host), int(port)

    def recv_one(self, peer: Peer, expected_command: str | None = None) -> Message:
        conn = self._require_conn(peer)

        header_bytes = self._recv_exact(conn.sock, NETWORK.HEADER_LENGTH)
        header = Header.from_bytes(header_bytes)

        if header.magic_bytes != self.magic_bytes:
            raise NetworkError(
                f"Unexpected network magic bytes: {header.magic_bytes.hex()} "
                f"(expected {self.magic_bytes.hex()})"
            )
        if expected_command is not None and header.command != expected_command:
            raise NetworkError(
                f"Unexpected command: {header.command!r} (expected {expected_command!r})"
            )

        payload_bytes = self._recv_exact(conn.sock, header.size)

        # --- Validate header + payload
        if not validate_package(header, payload_bytes):
            raise NetworkError("Failed to validate header and payload")

        conn.last_rx = time.time()
        peer.note_activity()

        msg_cls = Message.get_registered(header.command)
        if msg_cls is None:
            logger.info(f"Received unsupported command {header.command!r} from {peer.host}:{peer.port}")
            msg_cls = UnknownMessage
        return msg_cls._from_validated_envelope(header, payload_bytes)

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
