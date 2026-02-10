"""
Various Network type Enum classes
"""
from enum import IntFlag, Enum

__all__ = ["Services", "InvType", "PeerState", "RejectType", "RejectType"]


class Services(IntFlag):
    UNNAMED = 0x00
    NODE_NETWORK = 0x01
    NODE_GETUTXO = 0x02
    NODE_BLOOM = 0x04
    NODE_WITNESS = 0x08
    NODE_XTHIN = 0x10
    NODE_NETWORK_LIMITED = 0x0400


class InvType(IntFlag):
    ERROR = 0x00
    MSG_TX = 0x01
    MSG_BLOCK = 0x02
    MSG_FILTERED_BLOCK = 0x03
    MSG_CMPCT_BLOCK = 0x04
    MSG_WITNESS_TX = 0x40000001
    MSG_WITNESS_BLOCK = 0x40000002
    MSG_FILTERED_WITNESS_BLOCK = 0x40000003


class RejectType(IntFlag):
    REJECT_MALFORMED = 0x01
    REJECT_INVALID = 0x10
    REJECT_OBSOLETE = 0x11
    REJECT_DUPLICATE = 0x12
    REJECT_NONSTANDARD = 0x40
    REJECT_DUST = 0x41
    REJECT_INSUFFICIENTFEE = 0x42
    REJECT_CHECKPOINT = 0x43


class PeerState(Enum):
    """State of the peer connection"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    HANDSHAKING = "handshaking"
    READY = "ready"
    DISCONNECTING = "disconnecting"
