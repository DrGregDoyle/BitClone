"""
The Class which represents a peer in the network
"""

from src.network.network_data import NetAddr


class Peer:
    """
    An infoclass which represents a peer in the network
    """

    def __init__(self, net_addr: NetAddr):
        self.net_addr = net_addr
