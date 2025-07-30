"""
Base classes for Bitcoin protocol control messages
"""
from abc import ABC, abstractmethod
from io import BytesIO

from src.data import BitcoinFormats, Serializable, Header

__all__ = ["Message"]

MB = BitcoinFormats.MagicBytes.DEFAULT


class Message(Serializable, ABC):
    """
    All Bitcoin‐protocol messages inherit from this.
    We fix the magic bytes to be default for all messages
    The `is_data` flag distinguishes control vs. data.
    """
    _registry: dict[str, type["Message"]] = {}

    def __init__(self, is_data: bool = True):
        self.magic_bytes = MB  # Hardcoded to default magic bytes in all messages
        self.is_data = is_data

    def __init_subclass__(cls, **kw):
        super().__init_subclass__(**kw)
        cmd = getattr(cls, "COMMAND", None)
        if cmd:  # only concrete subclasses have COMMAND
            cls._registry[cmd] = cls

    # --- ABSTRACT METHODS FOR MESSAGING --- #

    @classmethod
    @abstractmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        """
        Deserialize an instance from its byte representation.
        """
        raise NotImplementedError(f"{cls.__name__} must implement from_bytes()")

    @abstractmethod
    def payload(self) -> bytes:
        """Return the payload of the message"""
        raise NotImplementedError(f"{self.__class__.__name__} must implement payload()")

    @abstractmethod
    def payload_dict(self) -> dict:
        """Return a dictionary of payload values for display"""
        raise NotImplementedError(f"{self.__class__.__name__} must implement payload_dict()")

    # --- MESSAGE PROPERTIES --- #

    def header(self) -> Header:
        """Return the Header object associated with the payload"""
        return Header.from_payload(
            payload=self.payload(),
            command=self.COMMAND,  # ignore type
            magic_bytes=self.magic_bytes
        )

    def to_bytes(self) -> bytes:
        """Serialize the full message to bytes according to the Bitcoin protocol."""
        return self.header().to_bytes() + self.payload()

    def to_dict(self) -> dict:
        return {
            "header": self.header().to_dict(),
            "payload": self.payload_dict(),
            "type": "data" if self.is_data else "control",
        }

    @property
    def message(self):
        return self.to_bytes()
