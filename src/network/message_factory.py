"""
Factory functions for creating network messages
"""
import time

from src.data.network_data import NetAddr
from src.network.ctrl_msg import Version, Ping, VerAck
from src.network.network_types import Services

__all__ = ["create_version_msg", "create_ping_msg", "create_verack_msg"]


def create_version_msg(protocol_version: int, services: int | Services, remote_addr: NetAddr, local_addr: NetAddr,
                       nonce: int, user_agent: str, last_block: int) -> Version:
    """Create a version message for initial peer handshake"""
    timestamp = int(time.time())
    return Version(
        protocol_version, services, timestamp, remote_addr, local_addr, nonce, user_agent, last_block
    )


def create_ping_msg(nonce: int) -> Ping:
    """Create a ping message"""
    return Ping(nonce)


def create_verack_msg() -> VerAck:
    """Create a verack acknowledgment message"""
    return VerAck()
