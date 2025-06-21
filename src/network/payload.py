"""
The Parent class for all Payload types
"""
# payload.py

import json
from abc import ABC, abstractmethod

from src.data import MAINNET
from src.network.header import Header


class Payload(ABC):
    """
    Abstract base for all payloads. Implements serialization interface directly.
    """
    # Byte Sizes
    PORT_BYTES = 2
    VERSION_BYTES = LAST_BLOCK_BYTES = 4
    SERVICE_BYTES = TIME_BYTES = NONCE_BYTES = 8
    IP_BYTES = 16

    @classmethod
    @abstractmethod
    def from_bytes(cls, byte_stream):
        """Deserialize from bytes."""
        raise NotImplementedError

    @abstractmethod
    def payload(self) -> bytes:
        """Serialize to bytes."""
        raise NotImplementedError

    @property
    @abstractmethod
    def command(self) -> str:
        """Return the Bitcoin message command name (e.g., 'version', 'ping')."""
        raise NotImplementedError

    def get_header(self, magic_bytes: bytes = MAINNET):
        """Return the corresponding Header for this payload."""
        payload_bytes = self.payload()
        return Header.from_payload(payload_bytes, self.command, magic_bytes)

    def get_message(self, magic_bytes: bytes = MAINNET):
        header = self.get_header(magic_bytes)
        return header.to_bytes() + self.payload()

    @abstractmethod
    def to_dict(self) -> dict:
        """Return a dict representation."""
        raise NotImplementedError

    def to_json(self) -> str:
        """Return a pretty-printed JSON string of the object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other) -> bool:
        """Compare by byte serialization."""
        # Accepts other Payloads or Serializables
        if not hasattr(other, "to_bytes"):
            return NotImplemented
        return self.payload() == other.payload()

    def __repr__(self) -> str:
        attrs = ", ".join(f"{k}={v!r}" for k, v in self.to_dict().items())
        return f"{self.__class__.__name__}({attrs})"


