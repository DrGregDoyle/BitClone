"""
The Serializable class. Formats all Blockchain elements into one standard
"""
import json

from src.library.data_handling import check_hex


class Serializable:
    """
    A base class that defines the interface for serializing and
    deserializing data to and from Bitcoin's wire format.
    """
    __slots__ = ()

    # -- Constants for fixed-size fields
    VERSION = 2  # Default

    # -- Common Byte values
    TXID_BYTES = MERKLEROOT_BYTES = 32
    AMOUNT_BYTES = 8
    VOUT_BYTES = SEQ_BYTES = VERSION_BYTES = LOCKTIME_BYTES = TIME_BYTES = BITS_BYTES = NONCE_BYTES = 4
    MARKERFLAG_BYTES = 2

    @classmethod
    def from_bytes(cls, byte_stream):
        raise NotImplementedError(f"{cls.__name__} must implement from_bytes()")

    @classmethod
    def from_hex(cls, hex_string: str):
        hex_string = check_hex(hex_string)
        if len(hex_string) % 2 != 0:
            raise ValueError(f"Invalid hex length for {cls.__name__}")
        return cls.from_bytes(bytes.fromhex(hex_string))

    @property
    def length(self):
        """
        Gives length of the given to_byte serialization
        """
        return len(self.to_bytes())

    def to_bytes(self) -> bytes:
        raise NotImplementedError(f"{self.__class__.__name__} must implement to_bytes()")

    def to_dict(self) -> dict:
        raise NotImplementedError(f"{self.__class__.__name__} must implement to_dict()")

    def to_json(self) -> str:
        """ Convert the object to a JSON string. """
        return json.dumps(self.to_dict(), indent=2)

    def __repr__(self) -> str:
        """ Return a human-readable JSON representation of the object. """
        return self.to_json()

    def __eq__(self, other):
        """
        Compares two Serializable instances based on their to_bytes() output.
        """
        if not isinstance(other, Serializable):
            return NotImplemented
        return self.to_bytes() == other.to_bytes()
