import asyncio

from src.network.datatypes.network_types import PeerState
from src.network.listener import AsyncPeerListener


def test_async_listener_accepts_and_dispatches_connection():
    async def scenario():
        handled = asyncio.Event()
        received = {}

        async def handler(connection):
            received["state"] = connection.peer.state
            received["host"] = str(connection.peer.host)
            received["payload"] = await connection.reader.readexactly(4)
            handled.set()

        listener = AsyncPeerListener(handler, host="127.0.0.1", port=0)
        async with listener:
            assert listener.is_listening
            host, port = listener.addresses[0][:2]
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(b"ping")
            await writer.drain()
            await asyncio.wait_for(handled.wait(), timeout=1)
            await asyncio.wait_for(reader.read(), timeout=1)
            writer.close()
            await writer.wait_closed()

        assert received == {
            "state": PeerState.CONNECTED,
            "host": "127.0.0.1",
            "payload": b"ping",
        }
        assert not listener.is_listening
        assert listener.connection_count == 0

    asyncio.run(scenario())


def test_async_listener_start_and_stop_are_idempotent():
    async def scenario():
        async def handler(connection):
            pass

        listener = AsyncPeerListener(handler, host="127.0.0.1", port=0)
        assert listener.addresses == ()

        await listener.start()
        addresses = listener.addresses
        await listener.start()

        assert listener.is_listening
        assert listener.addresses == addresses
        assert addresses[0][1] > 0

        await listener.stop()
        await listener.stop()

        assert not listener.is_listening
        assert listener.addresses == ()

    asyncio.run(scenario())


def test_async_listener_stop_closes_active_connections():
    async def scenario():
        accepted = asyncio.Event()

        async def handler(connection):
            accepted.set()
            await asyncio.Event().wait()

        listener = AsyncPeerListener(handler, host="127.0.0.1", port=0)
        await listener.start()
        host, port = listener.addresses[0][:2]
        reader, writer = await asyncio.open_connection(host, port)
        await asyncio.wait_for(accepted.wait(), timeout=1)

        assert listener.connection_count == 1
        await listener.stop()

        assert await asyncio.wait_for(reader.read(), timeout=1) == b""
        assert listener.connection_count == 0
        writer.close()
        await writer.wait_closed()

    asyncio.run(scenario())
