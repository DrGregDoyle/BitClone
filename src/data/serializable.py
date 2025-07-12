import json
from abc import ABC, abstractmethod
from io import BytesIO


class Serializable(ABC):
    """
    A base class that defines serialization and deserialization interfaces
    for Bitcoin protocol objects.
    """

    # Protocol constants 
    VERSION = 2

    # Field sizes in bytes
    HEADER_BYTES = 80
    TXID_BYTES = MERKLEROOT_BYTES = PREV_BLOCK_BYTES = 32
    COMMAND_BYTES = 12
    AMOUNT_BYTES = 8
    VOUT_BYTES = SEQ_BYTES = VERSION_BYTES = LOCKTIME_BYTES = TIME_BYTES = BITS_BYTES = NONCE_BYTES = SIGHASH_BYTES = \
        MB_BYTES = SIZE_BYTES = CHECKSUM_BYTES = 4
    MARKERFLAG_BYTES = 2

    @classmethod
    @abstractmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        """
        Deserialize an instance from its byte representation.
        """
        raise NotImplementedError(f"{cls.__name__} must implement from_bytes()")

    @property
    def length(self) -> int:
        """Return the length in bytes of the serialized form."""
        return len(self.to_bytes())

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Serialize the object to bytes according to the Bitcoin protocol."""
        raise NotImplementedError(f"{self.__class__.__name__} must implement to_bytes()")

    @abstractmethod
    def to_dict(self) -> dict:
        """Return a dictionary representation of the object."""
        raise NotImplementedError(f"{self.__class__.__name__} must implement to_dict()")

    def to_json(self) -> str:
        """Return a pretty-printed JSON string of the object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other) -> bool:
        """Compare two Serializable instances based on their byte representation."""
        if not isinstance(other, Serializable):
            return NotImplemented
        return self.to_bytes() == other.to_bytes()

    def __repr__(self) -> str:
        """Return a detailed string representation of the object."""
        attrs = ", ".join(f"{k}={v!r}" for k, v in self.to_dict().items())
        return f"{self.__class__.__name__}({attrs})"
