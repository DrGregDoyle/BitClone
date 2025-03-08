"""
Classes for BTCNum and BTCStack
"""
from collections import deque
from typing import List, Optional, TypeVar, Generic

from src.library.Script.stackerr import *

T = TypeVar('T')  # Generic type for stack elements


class BTCNum:
    """
    Represents a Bitcoin Script numeric value.

    Bitcoin Script uses a special encoding for integers:
    - Little-endian representation
    - Negative numbers set the sign bit (0x80) in the last byte
    - Zero is represented as an empty byte array
    - Limited to 4 bytes (32 bits) in standard consensus rules
    """

    # Bitcoin standard limits
    MAX_NUM_SIZE = 4  # Standard Bitcoin script limits integers to 4 bytes

    def __init__(self, value: int):
        """
        Initialize a BTCNum with a Python integer value.
        """
        self.value = value  # Store as Python int
        self.bytes = self._encode(self.value)

    @classmethod
    def from_bytes(cls, data: bytes):
        """
        Decode Bitcoin Script encoded integer bytes into a BTCNum object.
        """
        if data == b'':
            return cls(0)  # Empty bytes = 0

        # Check if data exceeds the maximum allowed size
        if len(data) > cls.MAX_NUM_SIZE:
            raise ValueError(f"Integer exceeds maximum size of {cls.MAX_NUM_SIZE} bytes")

        num = int.from_bytes(data, "little", signed=False)

        # Check if negative (Bitcoin sets the sign bit in last byte)
        if data[-1] & 0x80:
            num &= ~(1 << (8 * len(data) - 1))  # Clear sign bit using ~ to reverse bitmask
            num = -num

        return cls(num)

    def _encode(self, n: int) -> bytes:
        """
        Encode an integer to Bitcoin's minimal encoding format.
        """
        if n == 0:
            return b''  # Bitcoin represents 0 as empty bytes

        # Calculate minimum number of bytes needed
        abs_n = abs(n)
        num_bytes = (abs_n.bit_length() + 7) // 8 or 1

        # Check size limits
        if num_bytes > self.MAX_NUM_SIZE:
            raise ValueError(f"Integer too large: {n} requires {num_bytes} bytes, max is {self.MAX_NUM_SIZE}")

        abs_bytes = abs_n.to_bytes(num_bytes, "little")

        if n < 0:
            abs_bytes = bytearray(abs_bytes)
            abs_bytes[-1] |= 0x80  # Set sign bit in the last byte
            abs_bytes = bytes(abs_bytes)

        return abs_bytes

    # Arithmetic operations
    def __add__(self, other):
        if isinstance(other, BTCNum):
            return BTCNum(self.value + other.value)
        elif isinstance(other, int):
            return BTCNum(self.value + other)
        return NotImplemented

    def __radd__(self, other):
        # Handles cases like int + BTCNum
        if isinstance(other, int):
            return BTCNum(other + self.value)
        return NotImplemented

    def __sub__(self, other):
        if isinstance(other, BTCNum):
            return BTCNum(self.value - other.value)
        elif isinstance(other, int):
            return BTCNum(self.value - other)
        return NotImplemented

    def __rsub__(self, other):
        # Handles cases like int - BTCNum
        if isinstance(other, int):
            return BTCNum(other - self.value)
        return NotImplemented

    # Comparison operations
    def __eq__(self, other):
        """Check if two BTCNum values are equal."""
        if isinstance(other, BTCNum):
            return self.value == other.value
        return False

    def __lt__(self, other):
        """Check if this BTCNum is less than another."""
        if not isinstance(other, BTCNum):
            raise TypeError(f"Cannot compare BTCNum and {type(other)}")
        return self.value < other.value

    def __le__(self, other):
        """Check if this BTCNum is less than or equal to another."""
        if not isinstance(other, BTCNum):
            raise TypeError(f"Cannot compare BTCNum and {type(other)}")
        return self.value <= other.value

    def __gt__(self, other):
        """Check if this BTCNum is greater than another."""
        if not isinstance(other, BTCNum):
            raise TypeError(f"Cannot compare BTCNum and {type(other)}")
        return self.value > other.value

    def __ge__(self, other):
        """Check if this BTCNum is greater than or equal to another."""
        if not isinstance(other, BTCNum):
            raise TypeError(f"Cannot compare BTCNum and {type(other)}")
        return self.value >= other.value

    def __neg__(self):
        """Negate this BTCNum."""
        return BTCNum(-self.value)

    def __abs__(self):
        """Get the absolute value of this BTCNum."""
        return BTCNum(abs(self.value))

    def __int__(self):
        """Convert to Python int."""
        return self.value

    def __repr__(self):
        """String representation."""
        return f"BTCNum({self.value})"

    def __str__(self):
        """String representation."""
        return self.bytes.hex()


class BTCStack(Generic[T]):
    """
    A Bitcoin Script stack implementation using deque for efficient push/pop operations.
    The leftmost element (index 0) is the top of the stack.

    Following Bitcoin Script conventions:
    - The stack grows upward
    - Index 0 refers to the top item
    - Higher indices refer to deeper items in the stack
    """

    # Bitcoin has a maximum stack size in its consensus rules
    DEFAULT_MAX_SIZE = 1000

    def __init__(self, items: Optional[List[T]] = None, max_size: Optional[int] = DEFAULT_MAX_SIZE):
        """
        Initialize a new stack.

        Args:
            items: Optional initial items (will be pushed in reverse order)
            max_size: Maximum allowed items on the stack (None for unlimited)
        """
        self.max_size = max_size
        self.stack = deque()

        # Add initial items if provided
        if items:
            # Reverse to maintain expected order (last item in list becomes top of stack)
            for item in reversed(items):
                self.push(item)

    # Check functions for common validations
    def _check_not_empty(self) -> None:
        """
        Check if the stack is not empty.

        Raises:
            EmptyStackError: If the stack is empty
        """
        if self.is_empty:
            raise EmptyStackError("Stack is empty")

    def _check_index(self, index: int) -> None:
        """
        Check if an index is valid for the current stack.

        Args:
            index: The index to check

        Raises:
            StackIndexError: If the index is out of range
        """
        if index < 0 or index >= self.height:
            raise StackIndexError(f"Index out of range: {index}. Stack height: {self.height}")

    def _check_min_height(self, required: int) -> None:
        """
        Check if the stack has at least the required number of elements.

        Args:
            required: Minimum number of elements needed

        Raises:
            InsufficientElementsError: If the stack has fewer than required elements
        """
        if self.height < required:
            raise InsufficientElementsError(required=required, available=self.height)

    def _check_max_size(self, n: int = 1) -> None:
        """
        Check if the stack has room for one more element.

        Raises:
            StackError: If the stack would exceed its maximum size
        """
        if self.height + n >= self.max_size:
            raise StackError(f"Stack size would exceed maximum of {self.max_size}")

    # Core stack operations
    def push(self, element: T) -> None:
        """
        Push an element onto the stack.

        Args:
            element: The element to push

        Raises:
            StackError: If stack would exceed maximum size
        """
        self._check_max_size()
        self.stack.appendleft(element)

    def pushitems(self, items: list) -> None:
        """
        Push a list of items onto the stack
        """
        self._check_max_size(len(items))
        for item in items:
            self.stack.appendleft(item)

    def pop(self) -> T:
        """
        Pop the top element from the stack.

        Returns:
            The top element

        Raises:
            EmptyStackError: If the stack is empty
        """
        self._check_not_empty()
        return self.stack.popleft()

    def clear(self) -> None:
        """Clear all elements from the stack."""
        self.stack.clear()

    def pop_n(self, n: int) -> List[T]:
        """
        Pop n items from the stack at once.

        Args:
            n: Number of items to pop

        Returns:
            List of popped items (ordered from top to bottom)

        Raises:
            InsufficientElementsError: If the stack has fewer than n items
        """
        self._check_min_height(n)  # Check once if there are enough elements
        return [self.stack.popleft() for _ in range(n)]

    def peek(self, index: int = 0) -> T:
        """
        Return the element at the specified index without removing it.

        Args:
            index: Zero-based index (0 = top of stack)

        Returns:
            The element at the specified index

        Raises:
            StackIndexError: If the index is out of range
        """
        self._check_index(index)
        return self.stack[index]

    @property
    def top(self) -> T:
        """
        Return the top element of the stack without removing it.

        Returns:
            The top element

        Raises:
            EmptyStackError: If the stack is empty
        """
        self._check_not_empty()
        return self.stack[0]

    @property
    def height(self) -> int:
        """Return the current height (number of elements) of the stack."""
        return len(self.stack)

    @property
    def is_empty(self) -> bool:
        """Check if the stack is empty."""
        return self.height == 0

    def __len__(self) -> int:
        """Allow use of len() function on the stack."""
        return self.height

    def __bool__(self) -> bool:
        """Convert to boolean (True if not empty)."""
        return not self.is_empty

    def __repr__(self) -> str:
        """String representation of the stack."""
        items = list(self.stack)
        return f"BTCStack({items})"

    # Bitcoin Script specific stack operations
    def dup(self) -> None:
        """
        Duplicate the top stack item.

        Raises:
            EmptyStackError: If the stack is empty
        """
        self.push(self.top)

    def swap(self) -> None:
        """
        Swap the top two stack items.

        Raises:
            InsufficientElementsError: If there are fewer than 2 items on the stack
        """
        items = self.pop_n(2)
        self.pushitems(items)

    def rot(self) -> None:
        """
        Rotate the top three stack items.
        a b c -> b c a (where a is the top of the stack)

        Raises:
            InsufficientElementsError: If there are fewer than 3 items on the stack
        """
        items = self.pop_n(3)
        items = list(reversed(items[-1:] + items[:-1]))
        self.pushitems(items)

    def over(self) -> None:
        """
        Copy the second stack item to the top.
        a b -> a b a (where a is the top of the stack)

        Raises:
            InsufficientElementsError: If there are fewer than 2 items on the stack
        """
        self._check_min_height(2)
        self.push(self.peek(1))

    def pick(self, n: int) -> None:
        """
        Copy the nth stack item to the top.

        Args:
            n: The stack depth to copy from (0-based)

        Raises:
            StackIndexError: If n is out of range
        """
        self.push(self.peek(n))

    def roll(self, n: int) -> None:
        """
        Move the nth stack item to the top.

        Args:
            n: The stack depth to move from (0-based)

        Raises:
            StackIndexError: If n is out of range
        """
        items = self.pop_n(n + 1)  # Index starts at 0
        items = items[-1:] + items[:-1]
        self.pushitems(list(reversed(items)))

    def tuck(self) -> None:
        """
        Copy the top item and insert it below the second item.
        a b -> b a b (where a is the top of the stack)

        Raises:
            InsufficientElementsError: If there are fewer than 2 items on the stack
        """
        items = self.pop_n(2)  # items = [top, +1]
        items.append(items[0])  # items = [top, + 1, top]
        self.pushitems(items)  # list is a palindrome so order doesn't matter

    def nip(self):
        items = self.pop_n(2)
        self.push(items[0])
