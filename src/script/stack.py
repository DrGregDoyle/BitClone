"""
The classes for the BitStack and BitNum
"""
from src.core import SCRIPT, BitNumError

MAX = SCRIPT.MAX_BITNUM
COMMON = SCRIPT.COMMON_VALUES


class BitNum:
    """
    Represents a Bitcoin script numeric value.

    Bitcoin script uses a special encoding for integers:
    - Little-endian representation
    - Negative numbers set the sign bit (0x80) in the last byte
    - Zero is represented as an empty byte array
    - Limited to 4 bytes (32 bits) in standard consensus rules
    """
    __slots__ = ("_value", "_bytes_cache")

    def __init__(self, value: int):
        # --- Validation --- #
        if not isinstance(value, int):
            raise BitNumError("BitNum value must be an integer")

        # Get value and byte encoding
        self._value = value
        self._bytes_cache = COMMON.get(value)
        if self._bytes_cache is None:
            self._bytes_cache = self._encode(value)

    def _encode(self, n: int):
        """
        Encode an integer to Bitcoin's minimal encoding format.
        """
        # Zero case
        if n == 0:
            return b''  # Bitcoin represents 0 as empty bytes

        # Calculate minimum number of bytes needed
        abs_n = abs(n)
        num_bytes = (abs_n.bit_length() + 7) // 8 or 1

        # Check size
        if num_bytes > MAX:
            raise BitNumError("Integer too large to be BitNum encoded")

        abs_bytes = abs_n.to_bytes(num_bytes, "little")

        if n < 0:
            abs_bytes = bytearray(abs_bytes)
            abs_bytes[-1] |= 0x80  # Set sign bit in the last byte
            abs_bytes = bytes(abs_bytes)

        return abs_bytes

    @classmethod
    def from_bytes(cls, data: bytes):
        """
        Decode the encoded integer to a BitNum
        """
        # Zero case
        if data == b'':
            return cls(0)

        # Check size
        size = len(data)
        if size > MAX:
            raise BitNumError("Integer too large to be BitNum encoded")

        # int from bytes
        num = int.from_bytes(data, "little", signed=False)

        # If the sign bit is set in the last byte, interpret as a negative number.
        if data[-1] & 0x80:
            num &= ~(1 << (8 * len(data) - 1))  # Clear sign bit using ~ to reverse bitmask
            num = -num

        return cls(num)

