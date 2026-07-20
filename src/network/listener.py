"""Async TCP listener for inbound Bitcoin peer connections."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from src.core import NETWORK, get_logger
from src.network.datatypes.network_types import PeerState
from src.network.peer import Peer

__all__ = ["AsyncPeerListener", "InboundConnection", "InboundConnectionHandler"]

logger = get_logger(__name__)


@dataclass(slots=True)
class InboundConnection:
    """An accepted peer and its asyncio streams."""

    peer: Peer
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter


InboundConnectionHandler = Callable[[InboundConnection], Awaitable[None]]


class AsyncPeerListener:
    """Accept inbound peers and dispatch each connection to an async handler."""

    def __init__(
            self,
            handler: InboundConnectionHandler,
            host: str = "0.0.0.0",
            port: int = NETWORK.MAINNET_PORT,
    ):
        self.host = host
        self.port = port
        self._handler = handler
        self._server: asyncio.Server | None = None
        self._connections: dict[asyncio.Task, InboundConnection] = {}

    @property
    def is_listening(self) -> bool:
        return self._server is not None and self._server.is_serving()

    @property
    def addresses(self) -> tuple[tuple, ...]:
        """Return the bound socket addresses, including an ephemeral port."""
        if self._server is None or self._server.sockets is None:
            return ()
        return tuple(sock.getsockname() for sock in self._server.sockets)

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def start(self) -> None:
        """Start accepting connections; repeated calls are harmless."""
        if self.is_listening:
            return
        self._server = await asyncio.start_server(
            self._accept_connection,
            host=self.host,
            port=self.port,
        )

    async def stop(self) -> None:
        """Stop accepting peers and close all active inbound connections."""
        server, self._server = self._server, None
        if server is not None:
            server.close()

        current_task = asyncio.current_task()
        tasks = [task for task in self._connections if task is not current_task]
        for connection in self._connections.values():
            connection.writer.close()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if server is not None:
            await server.wait_closed()

    async def _accept_connection(
            self,
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
    ) -> None:
        peer_address = writer.get_extra_info("peername")
        host, port = str(peer_address[0]), int(peer_address[1])
        peer = Peer(host, port, state=PeerState.CONNECTED)
        connection = InboundConnection(peer, reader, writer)
        task = asyncio.current_task()
        if task is None:
            await self._close_writer(writer)
            return

        self._connections[task] = connection
        try:
            await self._handler(connection)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(f"Inbound peer handler failed for {peer.host}:{peer.port}")
        finally:
            peer.transition(PeerState.DISCONNECTED)
            self._connections.pop(task, None)
            await self._close_writer(writer)

    @staticmethod
    async def _close_writer(writer: asyncio.StreamWriter) -> None:
        """Close a stream without allowing peer behavior to stall shutdown."""
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1)
        except (TimeoutError, ConnectionError, OSError):
            writer.transport.abort()

    async def __aenter__(self) -> "AsyncPeerListener":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:
        await self.stop()
