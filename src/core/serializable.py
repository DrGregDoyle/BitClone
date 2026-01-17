"""
The Abstract Base Class for all serializable elements in BitClone
"""
import json
from abc import ABC, abstractmethod
from typing import TypeVar

from src.core.byte_stream import SERIALIZED

T = TypeVar("T", bound="Serializable")
__all__ = ["Serializable"]


# TODO: Updated Serializable to_dict method to be {"serialized": self.to_bytes().hex()} and then update each child
# TODO: Add format option for to_dict and to_json - so that values are either raw or BTC formatted
# class to call super().to_dict before creating their own to_dict
class Serializable(ABC):
    """
    A base class that defines serialization and deserialization interfaces
    for Bitcoin protocol objects.
    """

    @classmethod
    @abstractmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
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
    def to_dict(self, formatted: bool = True) -> dict:
        """Return a dictionary representation of the object. By default we return the serialized formatting in the
        dictionary. When formatted = False we return the instance variables.
        """
        raise NotImplementedError(f"{self.__class__.__name__} must implement to_dict()")

    def to_json(self, formatted: bool = True) -> str:
        """Return a pretty-printed JSON string of the object."""
        return json.dumps(self.to_dict(formatted), indent=2)

    def clone(self: T) -> T:
        """
        Return a deep copy via round-tripping through bytes.
        """
        return self.__class__.from_bytes(self.to_bytes())

    def __eq__(self, other) -> bool:
        """Compare two Serializable instances based on their byte representation."""
        if not isinstance(other, Serializable):
            return NotImplemented
        return self.to_bytes() == other.to_bytes()

    def __repr__(self) -> str:
        """Return a detailed string representation of the object."""
        attrs = ", ".join(f"{k}={v!r}" for k, v in self.to_dict().items())
        return f"{self.__class__.__name__}({attrs})"
