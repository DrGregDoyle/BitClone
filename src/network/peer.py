"""
The Peer class. Used to track information about remote Nodes
"""
from src.data.ip_utils import IP_ADDRESS


class Peer:

    def __init__(self, host: str | IP_ADDRESS, port: int):
        # Todo: Add on_message capabilities
        self.host = host
