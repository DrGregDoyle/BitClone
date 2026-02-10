"""
The Peer class. Used to track information about remote Nodes
"""
from src.network.messages.ctrl_msg import Version


class Peer:

    def __init__(self, version: Version):
        self.version = version

    def to_dict(self):
        return self.version.to_dict()
