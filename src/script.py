"""
Classes for executing and verifying scripts
"""
from collections import deque
from io import BytesIO
from typing import Any, Tuple, Callable, Dict

from src.library.data_handling import check_hex, check_length
from src.library.ecc import secp256k1
from src.library.op_codes import OPCODES
from src.logger import get_logger

logger = get_logger(__name__)


class Stack:
    """
    We use the deque class from the collections model to create a Stack class. This will be used in Script class for
    a stack of bytes. The stack can be viewed as a list of data running from left to right, where the left most
    element (i.e. the element indexed at 0) is the TOP of the stack.

    The Stack will implement various methods to be used by OP-codes
    """

    def __init__(self, items: list | None = None):
        self.stack = deque()
        if items:
            items = items[::-1]
            for i in items:
                self.push(i)

    def push(self, element: Any):
        self.stack.appendleft(element)

    def pop(self):
        try:
            return self.stack.popleft()
        except IndexError:
            raise IndexError("Popped from empty stack")

    def pop_two(self) -> Tuple[bytes, bytes]:
        """Pop two items from the stack at once."""
        if self.height < 2:
            raise IndexError("Not enough items on stack")
        return self.pop(), self.pop()

    def remove_at_index(self, n: int) -> bytes:
        """
        Remove and return the element at index n from the stack.
        Index 0 is the top of the stack.
        """
        if n < 0 or n >= self.height:
            raise IndexError("Index out of range")

        # Rotate the stack to bring the nth element to the leftmost position
        self.stack.rotate(-n)
        # Remove the leftmost element (which is the nth element)
        item = self.stack.popleft()
        # Rotate the stack back to its original order and return the popped item
        self.stack.rotate(n)
        return item

    def insert_below_index(self, item: bytes, n: int):
        """
        Inserts item into position below given index.
        Index begins at 0
        """
        if n < 0 or n >= self.height:
            raise IndexError("Index out of range")

        # Rotate the stack to bring the nth element to the leftmost position
        self.stack.rotate(-n)
        # Insert the item at the leftmost position (which is now below the nth element)
        self.stack.appendleft(item)
        # Rotate the stack back to its original order
        self.stack.rotate(n)

    @property
    def top(self):
        try:
            return self.stack[0]
        except IndexError:
            raise IndexError("Empty stack")

    @property
    def height(self):
        return len(self.stack)


class BTCNum:

    def __init__(self, value: int):
        self.value = value  # Store as Python int
        self.bytes = self._encode(self.value)

    @classmethod
    def from_bytes(cls, data: bytes):
        """Decodes a Bitcoin Script encoded integer into a BTCNum object."""
        if data == b'':
            return cls(0)  # Empty bytes = 0

        num = int.from_bytes(data, "little", signed=False)

        # Check if negative (Bitcoin sets sign bit in last byte)
        if data[-1] & 0x80:
            num &= ~(1 << (8 * len(data) - 1))  # Clear sign bit using ~ to reverse bitmask
            num = -num

        return cls(num)

    def _encode(self, n: int) -> bytes:
        """
        Encodes an integer to Bitcoin's minimal encoding format.

        - Uses little-endian representation.
        - Negative numbers set the sign bit (`0x80`) in the last byte.
        - `0` is represented as `b''` (empty bytes, per Bitcoin rules).
        """
        if n == 0:
            return b''  # Bitcoin represents 0 as empty bytes

        abs_n = abs(n).to_bytes((abs(n).bit_length() + 7) // 8 or 1, "little")

        if n < 0:
            abs_n = bytearray(abs_n)
            abs_n[-1] |= 0x80  # Set sign bit in the last byte

        return bytes(abs_n)

    def __add__(self, other):
        """Adds two BTCNum values."""
        return BTCNum(self.value + other.value)

    def __sub__(self, other):
        """Subtracts two BTCNum values."""
        return BTCNum(self.value - other.value)

    def __repr__(self):
        return f"BTCNum({self.value})"


class ScriptEngine:
    """
    A class for evaluating script.

    NOTE: All elements pushed to the stack should be bytes objects.
    """

    def __init__(self):
        """
        Setup stack and operation handlers
        """
        self.op_codes = OPCODES
        self.curve = secp256k1()
        self.stack = Stack()
        self.altstack = Stack()
        self.asm = []  # List of ASM instructions when evaluating script

        self.op_handlers = self._initialize_op_handlers()

    def _initialize_op_handlers(self) -> Dict[int, Callable]:
        return {
            0x00: self._op_false,
            0x4f: self._op_one_negate,
            0x61: self._op_nop,
            0x6b: self._op_to_altstack,
            0x6c: self._op_from_altstack,
            0x73: self._op_if_dup,
            0x74: self._op_depth,
            0x75: self._op_drop,
            0x76: self._op_dup,
            0x77: self._op_nip,
            0x78: self._op_over,
            0x79: self._op_pick,
            0x7a: self._op_roll,
            0x7b: self._op_rot,
            0x7c: self._op_swap,
            0x7d: self._op_tuck,
            0x6d: self._op_2drop,
            0x6e: self._op_2dup,
            0x6f: self._op_3dup,
            0x70: self._op_2over,
            0x71: self._op_2rot,
            0x72: self._op_2swap
        }
        # return {
        #     0x00: self._op_false,  # OP_0, OP_FALSE
        #     0x4c: self._push_data1,
        #     0x4d: self._push_data2,
        #     0x4e: self._push_data4,
        #     0x4f: None,  # self._op_negate,
        #     0x50: None,  # OP_RESERVED
        #     0x51: self.op_true,
        #     0x61: self._op_nop,
        #     0x69: self._op_verify,
        #     0x73: self._op_ifdup,
        #     0x74: self._op_depth,
        #     0x75: self._op_drop,
        #     0x76: self._op_dup,
        #     0x77: self._op_nip,
        #     0x78: self._op_over,
        #     0x79: self._op_pick,
        #     0x7a: self._op_roll,
        #     0x93: self._op_add,
        #     0x9a: self._op_booland,
        #     0x9b: self._op_boolor,
        #     0x9c: self._op_numeq,
        #     0x9d: self._op_numeq_verify,
        #     0x9e: self._op_numneq,
        #     0x9f: self._op_lt,
        #     0xa0: self._op_gt,
        #     0xa1: self._op_leq,
        #     0xa2: self._op_geq,
        #     0xa3: self._op_min,
        #     0xa4: self._op_max,
        # }

    def clear_stacks(self):
        """
        Will remove all elements from main and alt stack. CLears ASM instructions. Used in testing
        """
        while self.stack.height > 0:
            self.stack.pop()
        while self.altstack.height > 0:
            self.altstack.pop()
        self.asm = []

    def eval_script_from_hex(self, hex_script: hex):
        clean_hex_script = check_hex(hex_script)
        bytes_eval = self.eval_script(bytes.fromhex(clean_hex_script))
        return bytes_eval

    def eval_script(self, script: bytes, clear_stacks: bool = True) -> bool:
        """
        Evaluates the script - returns True/False based on results of main stack
        """
        # Empty stacks
        if clear_stacks:
            self.clear_stacks()

        # Get script as byte strem
        if not isinstance(script, (bytes, BytesIO)):
            raise ValueError(f"Expected byte data stream, received {type(script)}")
        stream = BytesIO(script) if isinstance(script, bytes) else script

        # Main loop
        while True:
            opcode = stream.read(1)
            if not opcode:
                break  # End of script

            opcode_int = int.from_bytes(opcode, "big")
            # logger.debug(f"OPCODE HEX: {opcode.hex()}")

            # Check for OP_PUSHBYTES_N
            if 0x00 < opcode_int < 0x4c:
                self._push_data(stream, opcode_int)
            # Check for OP_PUSHDATA_N
            elif 0x4c <= opcode_int <= 0x4e:
                match opcode_int:
                    case 0x4c:
                        self._asm_log("OP_PUSHDATA1")
                        self._push_data_n(stream, 1)  # Reads 1 byte for length encoding
                    case 0x4d:
                        self._asm_log("OP_PUSHDATA2")
                        self._push_data_n(stream, 2)  # Reads 2 bytes for length encoding
                    case 0x4e:
                        self._asm_log("OP_PUSHDATA4")
                        self._push_data_n(stream, 4)  # Reads 4 bytes for length encoding
            # Check for PushNum
            elif 0x50 < opcode_int < 0x61:
                num = opcode_int - 0x50
                self._asm_log(f"OP_{num}")
                self.stack.push(BTCNum(num).bytes)  # Push int from 1 to 16
            else:
                self._asm_log(OPCODES[opcode_int])  # Append corresponding ASM OP_CODE
                handler = self.op_handlers.get(opcode_int)
                if handler:
                    # Handle conditions here
                    # OP_IF 0x63
                    # OP_NOTIF 0x64
                    # OP_ELSE 0x67
                    # OP_ENDIF 0x68
                    # OP_VERIFY 0x69
                    # OP_RETURN 0x6a
                    if opcode_int == 0x69:  # OP_VERIFY
                        if not handler():
                            return False
                    else:
                        handler()
                else:
                    logger.debug(f"Unrecognized or invalid OP code; {opcode_int}")
                    return False

        # Validate stack
        return self._validate_stack()

    def _validate_stack(self):
        """
        A script is valid if the only element left on the stack is a OP_1 (or any non-zero value).

        A script is invalid if:
            -The final stack is empty
            -The only element left on the stack is OP_0
            -There is more than one element left on the stack at the end of execution.
            -The script exits prematurely (e.g. OP_RETURN).
        """
        # Proceed by stack height
        if self.stack.height == 0:
            self._asm_log("Script failed validation: Empty stack")
            return False
        elif self.stack.height == 1:
            # Check zero element
            if self.stack.top in [b'', b'\x00']:
                self._asm_log("Script failed validation: Zero value")
                return False
            self._asm_log("Script passes validation")
            return True
        else:
            self._asm_log("Script failed validation: Stack height > 1")
            return False

    # --- OP_CODE FUNCTIONS --- #
    def _op_false(self):
        self.stack.push(b'')

    def _push_data(self, stream: BytesIO, byte_length: int):
        """
        Pushes data stream of given byte_length to stack
        """
        # Get data | Check stream | Push to stack
        data = stream.read(byte_length)
        check_length(data, byte_length, "pushdata")
        self.stack.push(data)

        # Logging
        self._asm_log(f"OP_PUSHBYTES_{byte_length}")
        self._asm_log(data.hex())

    def _op_one_negate(self):
        self.stack.push(BTCNum(-1).bytes)

    def _op_nop(self):
        pass

    def _op_to_altstack(self):
        self.altstack.push(self.stack.pop())

    def _op_from_altstack(self):
        self.stack.push(self.altstack.pop())

    def _op_if_dup(self):
        if self.stack.top != b'':
            self.stack.push(self.stack.top)

    def _op_depth(self):
        self.stack.push(BTCNum(self.stack.height).bytes)

    def _op_drop(self):
        self.stack.pop()

    def _op_dup(self):
        self.stack.push(self.stack.top)

    def _op_nip(self):
        item, _ = self.stack.pop(), self.stack.pop()
        self.stack.push(item)

    def _op_over(self):
        item = self.stack.stack[1]  # 1 from the top
        self.stack.push(item)

    def _op_pick(self):
        pick_index_bytes = self.stack.pop()
        pick_index = BTCNum.from_bytes(pick_index_bytes).value
        logger.debug(f"PICK INDEX: {pick_index}")

        # Check height
        if self.stack.height <= pick_index:
            raise ValueError("Incorrect pick index")

        pick_item = self.stack.stack[pick_index]  # Indexed at 0
        self.stack.push(pick_item)

    def _op_roll(self):
        roll_index_bytes = self.stack.pop()
        roll_index = BTCNum.from_bytes(roll_index_bytes).value
        logger.debug(f"ROLL INDEX: {roll_index}")

        # Check height
        if self.stack.height <= roll_index:
            raise ValueError("Incorrect pick index")

        roll_item = self.stack.remove_at_index(roll_index)
        self.stack.push(roll_item)

    def _op_rot(self):
        item = self.stack.remove_at_index(2)
        self.stack.push(item)

    def _op_swap(self):
        item0, item1 = self.stack.pop(), self.stack.pop()
        self.stack.push(item0)
        self.stack.push(item1)

    def _op_tuck(self):
        item = self.stack.top
        popped_items = [self.stack.pop() for _ in range(2)]
        popped_items.append(item)
        for i in reversed(popped_items):
            self.stack.push(i)

        # --- OP_CODE HELPERS --- #

    def _op_2drop(self):
        self.stack.pop()
        self.stack.pop()

    def _op_2dup(self):
        items = [self.stack.stack[i] for i in range(1, -1, -1)]
        for item in items:
            self.stack.push(item)

    def _op_3dup(self):
        items = [self.stack.stack[i] for i in range(2, -1, -1)]
        for item in items:
            self.stack.push(item)

    def _op_2over(self):
        items = [self.stack.stack[i] for i in range(3, 1, -1)]
        for item in items:
            self.stack.push(item)

    def _op_2rot(self):
        popped_items = [self.stack.pop() for _ in range(6)]
        items = popped_items[-2:] + popped_items[:-2]
        for item in reversed(items):
            self.stack.push(item)

    def _op_2swap(self):
        popped_items = [self.stack.pop() for _ in range(4)]
        items = popped_items[-2:] + popped_items[:-2]
        for item in reversed(items):
            self.stack.push(item)

    # --- HELPERS --- #

    def _asm_log(self, log_string: str):
        self.asm.append(log_string)

    def _push_data_n(self, stream: BytesIO, length_bytes: int):
        """
        Generalized function to handle Bitcoin OP_PUSHDATA1, OP_PUSHDATA2, and OP_PUSHDATA4.
        Reads `length_bytes` from the stream to determine the number of bytes to push onto the stack.
        """
        stacklen = stream.read(length_bytes)
        byte_len = BTCNum.from_bytes(stacklen).value
        self._push_data(stream, byte_len)

    # ======================= #

    # ================================= #

    # def check_height(self, min_val: int, asm_code: str):
    #     """
    #     Checks to see that the stack height is greater than or equal to the min_val. If not, raise a valueError
    #     """
    #     if self.stack.height < min_val:
    #         raise ValueError(f"{asm_code} failed due to insuffcient stack height. Needed {min_val} but have "
    #                          f"{self.stack.height}")
    #

    #
    # def _op_verify(self) -> bool:
    #     """
    #     OP_VERIFY is an opcode that allows for quick validation of conditions without explicitly ending the script.
    #     It's used to ensure certain requirements are met.
    #
    #     Operation
    #         -Pop the top stack value.
    #         -If the value is 0 or an empty string, the script immediately fails and the transaction is considered
    #         invalid.
    #         -If the value is non-zero, continue executing the script, with the item now removed from the stack.
    #         -The primary use of OP_VERIFY is to verify that a certain condition holds without having to use
    #         conditional opcodes.
    #         -If the condition does not hold, the script will terminate at the OP_VERIFY step.
    #     """
    #     item = self.stack.pop()
    #     if item in [b'', b'\x00']:
    #         return False
    #     return True
    #
    # def _op_drop(self):
    #     """
    #     OP_DROP is used to remove the top item from the stack, effectively discarding it. This opcode is useful when
    #     you no longer need the top item and want to proceed with other operations on the remaining stack items.
    #
    #     Notes
    #         OP_DROP is often used to clean up intermediate values that are no longer needed in a script.
    #         If the stack is empty when OP_DROP is executed, the script will fail.
    #     """
    #     # Check height
    #     self.check_height(1, "OP_DROP")
    #
    #     # Pop
    #     self.stack.pop()
    #
    # def _op_dup(self):
    #     """
    #     OP_DUP is used to duplicate the top item on the stack, pushing a copy of it onto the stack. This opcode is
    #     frequently used in Bitcoin scripts to create copies of data, especially for validation purposes like
    #     signature checking.
    #
    #     NOTES:
    #         OP_DUP is commonly used in scripts like Pay-to-PubKeyHash (P2PKH) to duplicate the public key for
    #         signature verification.
    #         If the stack is empty when OP_DUP is executed, the script will fail.
    #     """
    #     # Check height
    #     if self.stack.height < 1:
    #         raise ValueError("Can't duplicate an empty stack")
    #
    #     # Push top element
    #     self.stack.push(self.stack.top)
    #
    # def _op_depth(self):
    #     """
    #     OP_DEPTH pushes the number of items on the stack onto the stack.
    #
    #     - The number is encoded as a Bitcoin Script integer (max 4 bytes, little-endian, signed).
    #     - An empty stack results in `b''` (Bitcoin's representation of `0`).
    #     """
    #     depth = self.stack.height
    #     depth_bytes = depth.to_bytes((depth.bit_length() + 7) // 8, "little", signed=True) if depth > 0 else b''
    #     self.stack.push(depth_bytes)
    #
    # def _op_nip(self):
    #     """
    #     OP_NIP is used to remove the second item from the top of the stack, while leaving the top item and the rest
    #     of the stack intact. This opcode is useful when you need to discard an intermediate value but keep the top
    #     item for further operations.
    #
    #     NOTES:
    #         OP_NIP allows you to efficiently discard the second stack item without disturbing the top of the stack.
    #         If there are fewer than two items on the stack when OP_NIP is executed, the script will fail.
    #     """
    #     # Check height
    #     self.check_height(2, "OP_NIP")
    #
    #     # Remove 2nd element
    #     del self.stack.stack[1]
    #
    # def _op_over(self):
    #     """
    #     OP_OVER is used to duplicate the second item from the stack (i.e., the value one over from the top).
    #
    #     NOTES:
    #         This opcode is part of a family of opcodes (OP_OVER, OP_2OVER, OP_DUP, and a few others) designed for
    #         duplication of stack items.
    #         If there are fewer than two items on the stack when OP_OVER is executed, the script will fail.
    #     """
    #     # Check height
    #     self.check_height(2, "OP_OVER")
    #
    #     # Duplicate 2nd item
    #     self.stack.push(self.stack.stack[1])  # Push a copy of the second element
    #
    # def _op_pick(self):
    #     """
    #     OP_PICK is used to select a stack item and copy it to the top.
    #
    #     NOTES:
    #         --If there are fewer than two items on the stack, if n is negative, or if n is larger than the stack when
    #         OP_PICK is executed, the script will fail.
    #         --The stack item just before OP_PICK dictates 'n', the location of the item to be copied.
    #         --Counting begins at 0, not 1; so an n value of 2 would reach the third stack item (0 is first,
    #         1 is second, 2 is third, and so on).
    #     """
    #     # Check height
    #     self.check_height(2, "OP_PICK")
    #
    #     # Pop the integer n (as a byte object) from the stack
    #     n_bytes = self.stack.pop()
    #
    #     # Convert the byte object (little-endian) to a signed integer
    #     n = int.from_bytes(n_bytes, byteorder='little', signed=True)
    #
    #     # Ensure n is a non-negative integer (OP_PICK does not support negative indices)
    #     if n < 0:
    #         raise ValueError("n must be a non-negative integer")
    #
    #     # Ensure there are at least n + 1 items on the stack
    #     if self.stack.height < n + 1:
    #         raise ValueError("Not enough items on the stack to pick from")
    #
    #     # Duplicate the n-th item (0-based index, left-to-right) and push it to the stack
    #     item = self.stack.stack[n]  # Index starts at 0
    #     self.stack.push(item)
    #
    # def _op_roll(self):
    #     """
    #     OP_ROLL is used to select a stack item and move it to the top.
    #
    #     NOTES:
    #         -If there are fewer than two items on the stack, if n is negative, or if n is larger than the stack when
    #             OP_ROLL is executed, the script will fail.
    #         -The stack item just before OP_ROLL dictates 'n', the location of the item to be moved.
    #         -Counting begins at 0, not 1; so an n value of 2 would reach the third stack item (0 is first,
    #             1 is second, 2 is third, and so on).
    #     """
    #     # Check height
    #     self.check_height(2, "OP_ROLL")
    #
    #     # Pop the integer n (as a byte object) from the stack
    #     n_bytes = self.stack.pop()
    #
    #     # Convert the byte object (little-endian) to a signed integer
    #     n = int.from_bytes(n_bytes, byteorder='little', signed=True)
    #
    #     # Ensure n is a non-negative integer (OP_ROLL does not support negative indices)
    #     if n < 0:
    #         raise ValueError("n must be a non-negative integer")
    #
    #     # Ensure there are at least n + 1 items on the stack
    #     if self.stack.height < n + 1:
    #         raise ValueError("Not enough items on the stack to pick from")
    #
    #     # Remove item at index n
    #     item = self.stack.remove_at_index(n)
    #     self.stack.push(item)
    #
    # def _op_ifdup(self):
    #     """
    #     OP_IFDUP duplicates the top item on the stack if and only if it is non-zero. If the top item is zero,
    #     the stack remains unchanged.
    #
    #     NOTES:
    #         This opcode is useful in conditional operations, where duplication occurs based on the value of the top
    #         stack item.
    #         A related opcode, OP_DUP, always duplicates the top stack item, regardless of its value.
    #     """
    #     # Push top element if it's not zero (an empty byte array)
    #     if self.stack.top != b'':
    #         self.stack.push(self.stack.top)
    #
    # # --- STACK COMPARISON --- #
    #
    # def _compare(self, operator, boolean_logic=False):
    #     """
    #     Generic comparison function that performs the operation specified by the operator.
    #     The operator should be a function that takes two integers and returns a boolean.
    #
    #     NOTES:
    #         Both items must be valid integers. Bitcoin Script interprets byte arrays up to 4 bytes as signed integers.
    #         An empty array ([]) is treated as 0 when compared.
    #         If there are fewer than two items on the stack when compare is called, the script will fail.
    #     """
    #     if self.stack.height < 2:
    #         raise ValueError("Comparison operation requires at least two elements on the stack")
    #
    #     # Get elements
    #     bytenum1 = self.stack.pop()
    #     bytenum2 = self.stack.pop()
    #
    #     # Check size
    #     if len(bytenum1) > 4 or len(bytenum2) > 4:
    #         raise ValueError("Stack elements must be no more than 4 bytes to be considered an integer")
    #
    #     # Transform to ints
    #     num1 = int.from_bytes(bytenum1, "big", signed=True)
    #     num2 = int.from_bytes(bytenum2, "big", signed=True)
    #
    #     # If boolean_logic is enabled, interpret values as truthy/falsy
    #     if boolean_logic:
    #         num1 = num1 != 0  # Convert to True (1) or False (0)
    #         num2 = num2 != 0
    #
    #     # Perform the comparison and push the result
    #     self.stack.push(b'\x01' if operator(num2, num1) else b'')
    #
    # def _op_add(self):
    #     """
    #     OP_ADD adds two numbers together and returns their sum on the stack.
    #
    #     The execution of the OP_ADD opcode involves three steps:
    #         1. Pop the top item from the stack.
    #         2. Pop the next top item from the stack.
    #         3. Add these two items together, and push the result back onto the stack.
    #     """
    #     self._compare(lambda x, y: x + y)
    #
    # def _op_min_max(self, comparison_func):
    #     """
    #     OP_MIN and OP_MAX compare the top two items on the stack as integers and push either
    #     the smaller (`OP_MIN`) or larger (`OP_MAX`) value back onto the stack.
    #
    #     Both original items are removed, and the selected value becomes the new top item.
    #
    #     Notes:
    #         - Both items must be valid integers (Bitcoin Script interprets byte arrays up to 4 bytes as integers).
    #         - An empty array (`b''`) is treated as 0 when compared.
    #         - If there are fewer than two items on the stack when executed, the script will fail.
    #
    #     param comparison_func: `max` for `OP_MAX`, `min` for `OP_MIN`.
    #     """
    #     if self.stack.height < 2:
    #         raise ValueError(f"{comparison_func.__name__.upper()} requires at least two elements on the stack")
    #
    #     # Get elements
    #     bytenum1 = self.stack.pop()
    #     bytenum2 = self.stack.pop()
    #
    #     # Check size
    #     if len(bytenum1) > 4 or len(bytenum2) > 4:
    #         raise ValueError("Stack elements must be no more than 4 bytes to be considered an integer")
    #
    #     # Transform to ints
    #     num1 = int.from_bytes(bytenum1, "big", signed=True)
    #     num2 = int.from_bytes(bytenum2, "big", signed=True)
    #
    #     # Get the min/max value
    #     result = comparison_func(num1, num2)
    #
    #     # Push the result onto the stack
    #     self.stack.push(result.to_bytes((result.bit_length() + 7) // 8 or 1, "big", signed=True))
    #
    # def _op_max(self):
    #     self._op_min_max(max)
    #
    # def _op_min(self):
    #     self._op_min_max(min)
    #
    # def _op_numneq(self):
    #     """
    #     OP_NUMNOTEQUAL compares the top two items on the stack as integers. If they are not numerically equal,
    #     it pushes 1 (true) onto the stack. If they are equal, it pushes an empty array (false). Both items are
    #     removed from the stack after the comparison.s
    #     """
    #     self._compare(lambda x, y: x != y)
    #
    # def _op_numeq(self):
    #     """
    #     OP_NUMEQUAL compares the top two items on the stack as integers. If they are numerically equal, it pushes 1 (
    #     true) onto the stack. If they are not equal, it pushes an empty array (false). Both items are removed from
    #     the stack after the comparison.
    #     """
    #     self._compare(lambda x, y: x == y)
    #
    # def _op_numeq_verify(self):
    #     """
    #     OP_NUMEQUALVERIFY combines the functionality of OP_NUMEQUAL and an implicit verification step. It compares
    #     the top two items on the stack as integers. If they are numerically equal, both items are removed,
    #     and the script continues execution. If they are not equal, the script fails immediately.
    #     """
    #     self._op_numeq()
    #     self._op_verify()
    #
    # def _op_boolor(self):
    #     """
    #     OP_BOOLOR performs a logical OR operation on the top two items on the stack. If either item is non-zero,
    #     it pushes 1 (true) onto the stack. If both items are zero (or empty arrays), it pushes an empty array (
    #     false). Both items are interpreted as integers, and must therefore be 4 bytes long or less. If either is
    #     above 4 bytes in length, the script is invalid.
    #     """
    #     self._compare(lambda x, y: x or y, boolean_logic=True)
    #
    # def _op_booland(self):
    #     """
    #     OP_BOOLAND performs a logical AND operation on the top two items on the stack. If both items are non-zero,
    #     it pushes 1 (true) onto the stack. If either item is zero (or an empty array), it pushes an empty array (
    #     false). Both items are interpreted as integers, and must therefore be 4 bytes long or less. If either is
    #     above 4 bytes in length, the script is invalid.
    #     """
    #     self._compare(lambda x, y: x and y, boolean_logic=True)
    #
    # def _op_geq(self):
    #     """
    #     OP_GREATERTHANOREQUAL compares the top two items on the stack as integers. If the second item is greater than
    #     or equal to the top item, it pushes 1 (true) onto the stack. If not, it pushes an empty array (false). Both
    #     items are removed from the stack after the comparison.
    #     """
    #     self._compare(lambda x, y: x >= y)
    #
    # def _op_leq(self):
    #     """
    #     OP_LESSTHANOREQUAL compares the top two items on the stack as integers. If the second item is less than or
    #     equal to the top item, it pushes 1 (true) onto the stack. If not, it pushes an empty array (false). Both
    #     items are removed from the stack after the comparison.
    #     """
    #     self._compare(lambda x, y: x <= y)
    #
    # def _op_lt(self):
    #     """
    #     OP_LESSTHAN compares the top two items on the stack as integers. If the second item is less than the top
    #     item, it pushes 1 (true) onto the stack. If not, it pushes an empty array (false). Both items are removed
    #     from the stack after the comparison.
    #     """
    #     self._compare(lambda x, y: x < y)
    #
    # def _op_gt(self):
    #     """
    #     OP_GREATERTHAN compares the top two items on the stack as integers. If the second item is greater than the
    #     top item, it pushes 1 (true) onto the stack. If not, it pushes an empty array (false). Both items are
    #     removed
    #     from the stack after the comparison.
    #     """
    #     self._compare(lambda x, y: x > y)
    #
    # # --- HASH FUNCTIONS --- #
    # def _op_hash(self, hash_func):
    #     """
    #     Generalized hash function for OP_SHA1, OP_HASH160, OP_SHA256, OP_HASH256, and OP_RIPEMD160.
    #
    #     This function replaces the top stack item with the result of applying the given hash function.
    #
    #     param hash_func: The hash function to apply. Can be one of:
    #         - `hash160(element)`: Applies RIPEMD-160(SHA-256(x)) (used in OP_HASH160)
    #         - `sha256(element)`: Applies SHA-256 (used in OP_SHA256)
    #         - `hash256(element)`: Applies SHA-256(SHA-256(x)) (used in OP_HASH256)
    #         - `ripemd160(element)`: Applies RIPEMD-160 (used in OP_RIPEMD160)
    #         - 'sha1(element)': Applies SHA-1 (used in OP_SHA1)
    #
    #     If the stack is empty, the script fails.
    #     """
    #     if self.stack.height < 1:
    #         raise ValueError(f"{hash_func.__name__.upper()} requires at least one element on the stack")
    #
    #     element = self.stack.pop()
    #     self.stack.push(hash_func(element))
    #
    # def _op_hash160(self):
    #     self._op_hash(hash160)
    #
    # def _op_sha256(self):
    #     self._op_hash(sha256)
    #
    # def _op_hash256(self):
    #     self._op_hash(hash256)
    #
    # def _op_ripemd160(self):
    #     self._op_hash(ripemd160)
    #
    # def _op_sha1(self):
    #     self._op_hash(sha1)


# --- TESTING

if __name__ == "__main__":
    test_script_hex = "5152535a5b7d"
    # test_script_bytes = bytes.fromhex(test_script_hex)
    engine = ScriptEngine()
    engine.eval_script_from_hex(test_script_hex)
    # print(f"ENGINE STACK: {engine.stack.top.hex()}")
    print(f"STACK HEIGHT: {engine.stack.height}")
    print(f"ASM CODE: {engine.asm}")
    print(f"---- MAIN STACK PRINTOUT ----")
    for s in range(engine.stack.height):
        temp_val = engine.stack.pop()
        print(f"STACK LEVEL: {s} || STACK ITEM: {temp_val.hex()}")
    print("--" * 20)
    print(f"---- ALT STACK PRINTOUT ----")
    for s in range(engine.stack.height):
        temp_val = engine.stack.pop()
        print(f"STACK LEVEL: {s} || STACK ITEM: {temp_val.hex()}")
    print("==" * 20)
