"""
The Message parent class
"""
from abc import ABC, abstractmethod

from src.core import Serializable, MAGICBYTES, SERIALIZED, get_stream, read_stream
from src.cryptography import hash256
from src.network import Header

DEFAULT_MAGIC = MAGICBYTES.MAINNET


class Message(Serializable, ABC):
    """
    A Message is composed of two parts: the message header and the message payload.
        -The header will be automatically created once the payload is finished
        -The children which inherit from Message will create the particular payload for their given class
        -The from_bytes and to_bytes method are assumed to comprise the whole message
        -We have from_payload and to_payload methods to handle the message payload
    """
    _registry: dict[str, type["Message"]] = {}
    __slots__ = ("magic_bytes",)

    def __init__(self):
        # Magic bytes are fixed per-network at object creation
        self.magic_bytes = DEFAULT_MAGIC

    def __init_subclass__(cls, **kw):
        """
        Called automatically when a subclass of Message is defined.
        Used here to auto-register new message classes by their COMMAND string, so they can be looked up later without
        manual bookkeeping.
        """
        super().__init_subclass__(**kw)
        cmd = getattr(cls, "COMMAND", None)
        if cmd:
            Message._registry[cmd] = cls

    @property
    def payload(self):
        """Lazily compute payload when accessed"""
        return self.to_payload()

    @property
    def message(self):
        """Avoid confusion between to_bytes and to_payload"""
        return self.to_bytes()

    # --- Message registry
    @classmethod
    def get_registered(cls, command: str):
        return cls._registry.get(command)

    # --- Header
    def _get_header(self, payload: bytes):
        command = getattr(self.__class__, "COMMAND", "testing")
        size = len(payload) if payload else 0
        checksum = hash256(payload)[:4] if payload else hash256(b'')[:4]
        return Header(command, size, checksum, self.magic_bytes)

    @classmethod
    @abstractmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        """Deserialize an instance from message payload."""
        raise NotImplementedError(f"{cls.__name__} must implement from_payload()")

    @abstractmethod
    def to_payload(self) -> bytes:
        """Serialize the instance to message payload."""
        raise NotImplementedError(f"{self.__name__} must implement to_payload()")

    @abstractmethod
    def payload_dict(self) -> dict:
        raise NotImplementedError(f"{self.__name__} must implement payload_dict()")

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        """Deserialize an instance from full message."""
        stream = get_stream(byte_stream)  # Get message
        header = Header.from_bytes(read_stream(stream, 24))  # Get header
        payload_bytes = read_stream(stream, header.size)  # Get message payload
        return cls.from_payload(payload_bytes)

    def to_bytes(self) -> bytes:
        """Serialize the instance to full message"""
        return self._get_header(self.payload).to_bytes() + self.to_payload()

    def to_dict(self) -> dict:
        return {
            "header": self._get_header(self.payload).to_dict(),
            "payload": self.payload_dict(),
        }


class EmptyMessage(Message):
    """
    Empty Message for various message types
    """
    __slots__ = ()

    def __init__(self):
        super().__init__()

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED = b''):
        return cls()

    def to_payload(self) -> bytes:
        return b''

    def payload_dict(self) -> dict:
        return {}


# --- TESTING
if __name__ == "__main__":
    test_msg = EmptyMessage()
    print(f"TEST MESSAGE: {test_msg.to_json()}")
