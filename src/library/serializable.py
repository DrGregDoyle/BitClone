"""
The Serializable class. Formats all Blockchain elements into one standard
"""

import json
from abc import ABC, abstractmethod
from io import BytesIO
from typing import ClassVar, Any, TypeVar

T = TypeVar('T', bound='Serializable')


class Serializable(ABC):
    """
    A base class that defines the interface for serializing and
    deserializing data to and from Bitcoin's wire format.

    This class provides a consistent interface for all Bitcoin protocol
    objects to serialize to and from bytes, hex, and JSON formats.
    """
    # Protocol constants
    VERSION: ClassVar[int] = 2

    # Field sizes in bytes
    TXID_BYTES: ClassVar[int] = 32
    MERKLEROOT_BYTES: ClassVar[int] = 32
    AMOUNT_BYTES: ClassVar[int] = 8
    VOUT_BYTES: ClassVar[int] = 4
    SEQ_BYTES: ClassVar[int] = 4
    VERSION_BYTES: ClassVar[int] = 4
    LOCKTIME_BYTES: ClassVar[int] = 4
    TIME_BYTES: ClassVar[int] = 4
    BITS_BYTES: ClassVar[int] = 4
    NONCE_BYTES: ClassVar[int] = 4
    MARKERFLAG_BYTES: ClassVar[int] = 2

    @classmethod
    @abstractmethod
    def from_bytes(cls: type[T], byte_stream: bytes | BytesIO) -> T:
        """
        Deserialize an instance from its byte representation.

        Args:
            byte_stream: Raw bytes or BytesIO stream to deserialize from

        Returns:
            A new instance of the class

        Raises:
            ValueError: If the byte stream is invalid
        """
        raise NotImplementedError(f"{cls.__name__} must implement from_bytes()")

    @classmethod
    def from_hex(cls: type[T], hex_string: str) -> T:
        """
        Create an instance from a hexadecimal string.

        Args:
            hex_string: Hex string to deserialize from (with or without '0x' prefix)

        Returns:
            A new instance of the class

        Raises:
            ValueError: If the hex string is invalid
        """
        # Remove 0x prefix if present
        hex_string = hex_string[2:] if hex_string.startswith('0x') else hex_string

        # Validate hex string
        if not all(c in "0123456789abcdefABCDEF" for c in hex_string):
            raise ValueError(f"Invalid hex characters in string: {hex_string}")
        if len(hex_string) % 2 != 0:
            raise ValueError(f"Invalid hex length for {cls.__name__}")

        return cls.from_bytes(bytes.fromhex(hex_string.lower()))

    @classmethod
    def from_json(cls: type[T], json_string: str) -> T:
        """
        Create an instance from a JSON string.

        Args:
            json_string: Valid JSON string representing the object

        Returns:
            A new instance of the class

        Raises:
            ValueError: If the JSON is invalid or missing required fields
        """
        try:
            data = json.loads(json_string)
            return cls(**data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")
        except TypeError as e:
            raise ValueError(f"Missing required fields: {e}")

    @property
    def length(self) -> int:
        """
        Get the length in bytes of the serialized form.

        Returns:
            Number of bytes in the serialized representation
        """
        return len(self.to_bytes())

    @abstractmethod
    def to_bytes(self) -> bytes:
        """
        Serialize the object to bytes according to the Bitcoin protocol.

        Returns:
            Raw bytes representation
        """
        raise NotImplementedError(f"{self.__class__.__name__} must implement to_bytes()")

    @abstractmethod
    def to_dict(self) -> dict[str, Any]:
        """
        Convert the object to a dictionary representation.

        Returns:
            Dictionary containing all relevant object data
        """
        raise NotImplementedError(f"{self.__class__.__name__} must implement to_dict()")

    def to_json(self) -> str:
        """
        Convert the object to a JSON string.

        Returns:
            Pretty-printed JSON string representation
        """
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: Any) -> bool:
        """
        Compare two Serializable instances based on their byte representation.

        Args:
            other: Object to compare with

        Returns:
            True if the objects serialize to the same bytes
        """
        if not isinstance(other, Serializable):
            return NotImplemented
        return self.to_bytes() == other.to_bytes()

    def __repr__(self) -> str:
        """
        Return a detailed string representation of the object.

        This implementation provides a clear view of the object's class
        and its data in a format that's both readable and informative
        for debugging purposes.

        Returns:
            String representation showing class name and key attributes
        """
        class_name = self.__class__.__name__
        attrs = {k: v for k, v in self.to_dict().items()}
        attr_str = ", ".join(f"{k}={v!r}" for k, v in attrs.items())
        return f"{class_name}({attr_str})"
