"""
Base classes for Bitcoin protocol control messages
"""
import json
from abc import ABC, abstractmethod
from io import BytesIO

from src.data import MAINNET
from src.network.header import Header

__all__ = ["ControlMessage", "DataMessage"]


# TODO: Change Control and Data message to inherit from Serializable

class ControlMessage(ABC):
    """
    Base class for all Bitcoin protocol control messages.
    Provides common functionality for message creation, serialization, and JSON output.
    """

    def __init__(self, magic_bytes: bytes = MAINNET):
        self.magic_bytes = magic_bytes

    @property
    @abstractmethod
    def command(self) -> str:
        """
        Return the command string for this message type.
        Must be implemented by subclasses.
        """
        raise NotImplementedError("Missing ascii command")

    @abstractmethod
    def payload(self) -> bytes:
        """
        Return the payload bytes for this message.
        Must be implemented by subclasses.
        """
        raise NotImplementedError("Missing payload function")

    def get_header(self) -> Header:
        """
        Generate the message header from the payload and command.
        """
        return Header.from_payload(self.payload(), self.command, self.magic_bytes)

    @property
    def message(self) -> bytes:
        """
        Return the complete message (header + payload) as bytes.
        """
        header = self.get_header()
        return header.to_bytes() + self.payload()

    def to_dict(self) -> dict:
        """
        Return a dictionary representation of the message.
        Subclasses should override _payload_dict() to provide payload-specific data.
        """
        header_dict = self.get_header().to_dict()
        payload_dict = self._payload_dict()
        return {"header": header_dict, "payload": payload_dict}

    def _payload_dict(self) -> dict:
        """
        Return payload-specific dictionary data.
        Subclasses should override this method to provide their payload data.
        Default implementation returns empty dict for messages with no payload.
        """
        return {}

    def to_json(self) -> str:
        """
        Return JSON representation of the message.
        """
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MAINNET):
        """
        Create message instance from bytes.
        Subclasses should override this method if they need to parse payload data.
        Default implementation creates instance with just magic_bytes (for empty payloads).
        """
        return cls(magic_bytes)


class DataMessage(ABC):
    """
    Base class for all Bitcoin protocol data messages.
    Provides common functionality for message creation, serialization, and JSON output.
    """

    def __init__(self, magic_bytes: bytes = MAINNET):
        self.magic_bytes = magic_bytes

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO, magic_bytes: bytes = MAINNET):
        """
        Create message instance from bytes.
        Subclasses should override this method if they need to parse payload data.
        Default implementation creates instance with just magic_bytes (for empty payloads).
        """
        return cls(magic_bytes)

    @property
    @abstractmethod
    def command(self) -> str:
        """
        Return the command string for this message type.
        Must be implemented by subclasses.
        """
        raise NotImplementedError("Missing ascii command")

    @abstractmethod
    def payload(self) -> bytes:
        """
        Return the payload bytes for this message.
        Must be implemented by subclasses.
        """
        raise NotImplementedError("Missing payload function")

    def get_header(self) -> Header:
        """
        Generate the message header from the payload and command.
        """
        return Header.from_payload(self.payload(), self.command, self.magic_bytes)

    @property
    def message(self) -> bytes:
        """
        Return the complete message (header + payload) as bytes.
        """
        header = self.get_header()
        return header.to_bytes() + self.payload()

    def to_dict(self) -> dict:
        """
        Return a dictionary representation of the message.
        Subclasses should override _payload_dict() to provide payload-specific data.
        """
        header_dict = self.get_header().to_dict()
        payload_dict = self._payload_dict()
        return {"header": header_dict, "payload": payload_dict}

    def _payload_dict(self) -> dict:
        """
        Return payload-specific dictionary data.
        Subclasses should override this method to provide their payload data.
        Default implementation returns empty dict for messages with no payload.
        """
        return {}

    def to_json(self) -> str:
        """
        Return JSON representation of the message.
        """
        return json.dumps(self.to_dict(), indent=2)
