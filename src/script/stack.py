"""
The classes for the BitStack and BitNum
"""
import json
from collections import deque
from typing import Any

from src.core import SCRIPT, BitNumError, BitStackError

MAX_BITNUM_BYTES = SCRIPT.MAX_BITNUM
MAX_STACK_ITEMS = SCRIPT.MAX_STACK
COMMON = SCRIPT.COMMON_VALUES

__all__ = ["BitNum", "BitStack", "StackItem"]


class BitNum:
    """
    Minimal-encoded signed-magnitude integers for Bitcoin Script.
    Stores the Python int and lazily caches the Script encoding (little-endian).

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

        self._value = value
        self._bytes_cache = None  # set lazily unless built by from_bytes

    def _encode(self, n: int) -> bytes:
        """Encode an int to Bitcoin Script's minimal signed-magnitude (little-endian) format."""
        if n == 0:
            return b""

        neg = n < 0
        a = -n if neg else n
        mag = a.to_bytes((a.bit_length() + 7) // 8, "little")

        # Size guard (predict result length without allocating):
        # Need one extra byte iff MSB bit would collide with sign.
        predicted_len = len(mag) + (1 if (mag[-1] & 0x80) else 0)
        if predicted_len > MAX_BITNUM_BYTES:
            raise BitNumError("Integer too large to be BitNum encoded")

        # The most significant bit of the most significant byte holds the sign encoding
        if mag[-1] & 0x80:
            # Add an extra byte to host the sign bit.
            return mag + (b"\x80" if neg else b"\x00")

        # Reuse top byte: set sign bit in place for negatives.
        if neg:
            return mag[:-1] + bytes([mag[-1] | 0x80])  # | is the OR bitwise operator

        return mag

    @property
    def value(self):
        return self._value

    @classmethod
    def from_bytes(cls, data: bytes):
        """
        Parse Bitcoin Script number (little-endian, sign bit in MSB of last byte).
        """
        # Zero case
        if data == b'':
            return cls(0)

        # Check size
        size = len(data)
        if size > MAX_BITNUM_BYTES:
            raise BitNumError("Integer too large to be BitNum encoded")

        # int from bytes
        num = int.from_bytes(data, "little", signed=False)

        # If the sign bit is set in the last byte, interpret as a negative number.
        if data[-1] & 0x80:
            num &= ~(1 << (8 * len(data) - 1))  # Clear sign bit using ~ to reverse bitmask
            num = -num

        return cls(num)

    def to_bytes(self) -> bytes:
        if self._bytes_cache is None:
            self._bytes_cache = self._encode(self._value)
        return self._bytes_cache

    # --- Arithmetic operations --- #

    def _extract_other(self, other: object) -> int:
        """
        Helper function to verify the object for the arithmetical function
        """
        if isinstance(other, BitNum):
            return other.value
        elif isinstance(other, int):
            return other
        elif isinstance(other, bytes):
            return BitNum.from_bytes(other).value  # Extract encoded number
        else:
            raise BitNumError(f"Incorrect type for BitNum operations: {type(other)}")

    def __add__(self, other: object) -> "BitNum":
        num = self._extract_other(other)
        return BitNum(self.value + num)

    def __radd__(self, other: object) -> "BitNum":
        return self.__add__(other)

    def __sub__(self, other: object) -> "BitNum":
        num = self._extract_other(other)
        return BitNum(self.value - num)

    def __rsub__(self, other: object) -> "BitNum":
        num = self._extract_other(other)
        return BitNum(num - self.value)

    def __eq__(self, other: object) -> bool:
        num = self._extract_other(other)
        return self.value == num

    def __lt__(self, other: object) -> bool:
        num = self._extract_other(other)
        return self.value < num

    def __le__(self, other: object) -> bool:
        num = self._extract_other(other)
        return self.value <= num

    def __gt__(self, other: object) -> bool:
        num = self._extract_other(other)
        return self.value > num

    def __ge__(self, other: object) -> bool:
        num = self._extract_other(other)
        return self.value >= num

    def __neg__(self) -> "BitNum":
        return BitNum(-self.value)

    def __abs__(self) -> "BitNum":
        return BitNum(abs(self.value))

    def __int__(self) -> int:
        return self.value

    def __repr__(self):
        return f"BitNum({self.value})"

    def __str__(self):
        """String representation."""
        if self._bytes_cache is None:
            return self.to_bytes().hex()
        return self._bytes_cache.hex()


# --- BITSTACK --- #
StackItem = bytes | BitNum


class BitStack:
    """
    A lightweight stack implementation for use in BitClone script
    """

    def __init__(self, items: list = None, max_size: int = MAX_STACK_ITEMS):
        """
        The stack is ordered so that the right-most element is at the top of the stack.
        Given a list, we apply the items from left to right, so that the first data will be at the bottom of the stack
        """
        self.max_size = max_size
        self.stack = deque()

        # Add initial items if provided
        if items:
            self.pushitems(items)

    # --- Stack Properties --- #
    @property
    def height(self) -> int:
        return len(self.stack)

    @property
    def is_empty(self) -> bool:
        return self.height == 0

    @property
    def top(self):
        if not self.is_empty:
            return self.stack[0]
        return None

    @property
    def bottom(self):
        if not self.is_empty:
            return self.stack[-1]
        return None

    # --- Internal Validation --- #
    def _check_max_size(self, n: int = 1):
        if self.height + n > self.max_size:
            raise BitStackError("Stack operations would exceed maximum size")

    def _check_min_height(self, n: int = 1):
        if self.height < n:
            raise BitStackError("Stack operations exeeds number of stack items")

    def _check_not_empty(self):
        if self.is_empty:
            raise BitStackError("Stack operations cannot be performed on empty stack")

    def _ensure_item_type(self, x: StackItem):
        if not isinstance(x, (bytes, BitNum)):
            raise BitStackError("Only bytes or BitNum are allowed on the BitStack")

    # --- Stack Ops --- #

    def push(self, item: StackItem):
        self._ensure_item_type(item)
        self._check_max_size()
        self.stack.appendleft(item.to_bytes() if isinstance(item, BitNum) else item)

    def pushitems(self, items: list[Any]):
        self._check_max_size(len(items))
        for item in items:
            self._ensure_item_type(item)
            self.stack.appendleft(item.to_bytes() if isinstance(item, BitNum) else item)

    def pop(self) -> Any:
        self._check_not_empty()
        return self.stack.popleft()

    def popitems(self, n: int) -> list:
        """
        Pop n items from the stack into a list. Leftmost element is the top
        """
        self._check_min_height(n)
        return [self.stack.popleft() for _ in range(n)]

    # --- Item Specific Helper Functions --- #

    def pushlist(self, items: list[StackItem]):
        """
        Push in reversed order so that elements at bottom of list end up on bottom of stack
        """
        self.pushitems(list(reversed(items)))

    def pushbool(self, boolean: bool):
        push_byte = b'\x01' if boolean else b''
        self.push(push_byte)

    def popnum(self) -> int:
        """
        Shortcut to pop BitNum values
        """
        top = self.pop()
        return BitNum.from_bytes(top).value

    def clear(self):
        self.stack.clear()

    # --- Dunder Ops --- #
    def __len__(self) -> int:
        """Allow use of len() function on the stack."""
        return self.height

    # --- Display --- #
    def to_dict(self):
        stack_dict = {}
        # Empty stack returns empty dict
        if not self.is_empty:
            for i, item in enumerate(self.stack):
                # Format data | bytes else BitNum
                item = item.hex() if isinstance(item, bytes) else item.value
                stack_dict.update({i: item})
        return stack_dict

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)
