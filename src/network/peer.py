"""
The Peer class: Will contain relevant information about Peer status for the network
"""

from typing import Optional

from src.network.ctrl_msg import Version
from src.network.network_data import NetAddr, Services
from src.network.network_types import PeerState

__all__ = ["Peer"]


class Peer:
    """
    Represents a Bitcoin network peer (connected or disconnected)
    """

    def __init__(self, ip_addr: str, port: int = 8333):
        self.ip_addr = ip_addr
        self.port = port

        # Connection state
        self.state = PeerState.DISCONNECTED
        self.connected_at: Optional[float] = None
        self.disconnected_at: Optional[float] = None

        # Peer information (populated during handshake)
        self.protocol_version: Optional[int] = None
        self.services: Optional[Services] = None
        self.user_agent: Optional[str] = None
        self.last_block: Optional[int] = None
        self.remote_netaddr: Optional[NetAddr] = None

        # Statistics
        self.bytes_sent: int = 0
        self.bytes_received: int = 0
        self.messages_sent: int = 0
        self.messages_received: int = 0
        self.last_message_time: Optional[float] = None

    def update_from_version(self, version_msg: Version):
        """Update peer information from their version message"""
        self.protocol_version = version_msg.protocol_version
        self.services = version_msg.services
        self.user_agent = version_msg.user_agent
        self.last_block = version_msg.last_block
        self.remote_netaddr = version_msg.local_net_addr

    def __repr__(self):
        return f"Peer({self.ip_addr}:{self.port}, state={self.state.value})"

    def to_dict(self) -> dict:
        return {
            "ip_addr": self.ip_addr,
            "port": self.port,
            "state": self.state.value,
            "protocol_version": self.protocol_version,
            "user_agent": self.user_agent,
            "last_block": self.last_block,
            "connected_at": self.connected_at,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "messages_sent": self.messages_sent,
            "messages_received": self.messages_received,
        }
