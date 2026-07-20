"""
The Message parent class
"""
from abc import ABC, abstractmethod

from src.core import Serializable, MAGICBYTES, SERIALIZED, get_stream, read_stream, get_logger, NETWORK
from src.cryptography import hash256
from src.network.messages.header import Header

__all__ = ["Message", "validate_package", "EmptyMessage", "UnknownMessage"]

logger = get_logger(__name__)


def validate_package(header: Header, payload: bytes) -> bool:
    """
    We validate the Header values against the payload
    """
    calc_checksum = hash256(payload)[:NETWORK.CHECKSUM_LENGTH]
    calc_size = len(payload)

    # checksum
    if calc_checksum != header.checksum:
        logger.error("Message checksum mismatch")
        return False
    # size
    if calc_size != header.size:
        logger.error("Message size mismatch")
        return False
    # magic_bytes
    if header.magic_bytes not in MAGICBYTES.ALLOWED_MAGIC:
        logger.error("Message magic bytes mismatch")
        return False
    return True


class Message(Serializable, ABC):
    """
    A Message is composed of two parts: the message header and the message payload.
        -The header will be automatically created once the payload is finished
        -The children which inherit from Message will create the particular payload for their given class
        -The from_bytes and to_bytes method are assumed to comprise the whole message
        -We have from_payload and to_payload methods to handle the message payload
    =================================================================================
    |   name            |   datatype    |   serialzed format        |   byte size   |
    =================================================================================
    |   header          |   Header      |   header.to_bytes()       |   24          |
    |   payload         |   Message     |   message.to_payload()    |  var          |
    =================================================================================
    """
    _registry: dict[str, type["Message"]] = {}
    __slots__ = ("magic_bytes",)

    def __init__(self, magic_bytes: bytes = MAGICBYTES.MAINNET):
        # Magic bytes are fixed per-network at object creation
        self.magic_bytes = magic_bytes

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
    def header(self):
        """Lazily compute header when accessed"""
        return self._get_header(self.payload)

    @property
    def message(self):
        """Avoid confusion between to_bytes and to_payload"""
        return self.to_bytes()

    # --- Message registry
    @classmethod
    def get_registered(cls, command: str):
        return cls._registry.get(command)

    @classmethod
    def registered_commands(cls) -> frozenset[str]:
        """Return an immutable snapshot of the currently registered commands."""
        return frozenset(cls._registry)

    # --- Header
    def _get_header(self, payload: bytes):
        command = getattr(self.__class__, "COMMAND", "testing")
        size = len(payload) if payload else 0
        checksum = hash256(payload)[:NETWORK.CHECKSUM_LENGTH]
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

    @abstractmethod
    def payload_data(self) -> dict:
        raise NotImplementedError(f"{self.__name__} must implement payload_data()")

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        """Deserialize an instance from full message."""
        stream = get_stream(byte_stream)  # Get message
        header = Header.from_bytes(read_stream(stream, NETWORK.HEADER_LENGTH))
        payload_bytes = read_stream(stream, header.size)  # Get message payload

        return cls.from_envelope(header, payload_bytes)

    @classmethod
    def from_envelope(cls, header: Header, payload: bytes):
        """Decode an already-separated message envelope without reparsing it."""
        if not validate_package(header, payload):
            raise ValueError("Package fails validation")
        return cls._from_validated_envelope(header, payload)

    @classmethod
    def _from_validated_envelope(cls, header: Header, payload: bytes):
        """Decode an envelope that the caller has already validated."""
        command = getattr(cls, "COMMAND", None)
        if command is not None and header.command != command:
            raise ValueError(
                f"Header command {header.command!r} does not match {command!r}"
            )

        message = cls.from_payload(payload)
        message.magic_bytes = header.magic_bytes
        return message

    def to_bytes(self) -> bytes:
        """Serialize the instance to full message"""
        payload = self.to_payload()
        return self._get_header(payload).to_bytes() + payload

    def to_dict(self) -> dict:
        payload = self.to_payload()
        return {
            "header": self._get_header(payload).to_dict(),
            "payload": self.payload_dict(),
        }

    def to_data(self) -> dict:
        payload = self.to_payload()
        return {
            "header": self._get_header(payload).to_data(),
            "payload": self.payload_data()
        }


class EmptyMessage(Message):
    """
    Empty Message for various message types
    """
    __slots__ = ()

    def __init__(self, magic_bytes: bytes = MAGICBYTES.MAINNET):
        super().__init__(magic_bytes=magic_bytes)

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED = b''):
        return cls()

    def to_payload(self) -> bytes:
        return b''

    def payload_dict(self) -> dict:
        return {}

    def payload_data(self) -> dict:
        return {}


class UnknownMessage(Message):
    """A validly framed message whose command BitClone does not implement."""
    COMMAND = None
    __slots__ = ("command", "raw_payload")

    def __init__(self, command: str, payload: bytes, magic_bytes: bytes):
        super().__init__(magic_bytes=magic_bytes)
        self.command = command
        self.raw_payload = payload

    @classmethod
    def _from_validated_envelope(cls, header: Header, payload: bytes):
        return cls(header.command, payload, header.magic_bytes)

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        raise TypeError("UnknownMessage requires command and network-magic context")

    def _get_header(self, payload: bytes):
        checksum = hash256(payload)[:NETWORK.CHECKSUM_LENGTH]
        return Header(self.command, len(payload), checksum, self.magic_bytes)

    def to_payload(self) -> bytes:
        return self.raw_payload

    def payload_dict(self) -> dict:
        return {"raw_payload": self.raw_payload.hex()}

    def payload_data(self) -> dict:
        return {"command": self.command, "raw_payload": self.raw_payload.hex()}


# --- TESTING
if __name__ == "__main__":
    test_msg = EmptyMessage()
    print(f"TEST MESSAGE: {test_msg.to_json()}")
