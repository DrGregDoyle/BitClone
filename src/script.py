"""
Classes for executing and verifying scripts
"""
from collections import deque
from io import BytesIO
from typing import Any, Callable, Dict, List

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
        self.stack = deque(items[::-1]) if items else deque()

    def push(self, element: Any) -> None:
        """Push an element onto the stack"""
        self.stack.appendleft(element)

    def pop(self):
        try:
            return self.stack.popleft()
        except IndexError:
            raise IndexError("Popped from empty stack")

    def clear(self) -> None:
        """Clear the stack"""
        self.stack.clear()

    def pop_n(self, n: int) -> List[bytes]:
        """Pop n items from the stack at once."""
        if self.height < n:
            raise IndexError(f"Not enough items on stack. Required: {n}, Available: {self.height}")
        return [self.pop() for _ in range(n)]

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

    def peek(self, n: int = 0) -> bytes:
        """Return the element at index n without removing it"""
        if n < 0 or n >= self.height:
            raise IndexError(f"Index out of range: {n}. Stack height: {self.height}")
        return self.stack[n]

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
    BTCZero = [b'', b'\x00']

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
            # Constants
            0x00: self._op_false,  # OP_0, OP_FALSE
            0x51: self._op_true,  # OP_1, OP_TRUE
            0x4f: self._op_1negate,  # OP_1NEGATE

            # Flow control
            0x61: self._op_nop,  # OP_NOP
            0x63: self._op_if,  # OP_IF
            0x64: self._op_notif,  # OP_NOTIF
            0x67: self._op_else,  # OP_ELSE
            0x68: self._op_endif,  # OP_ENDIF
            0x69: self._op_verify,  # OP_VERIFY
            0x6a: self._op_return,  # OP_RETURN

            # Stack operations
            0x6b: self._op_to_altstack,  # OP_TOALTSTACK
            0x6c: self._op_from_altstack,  # OP_FROMALTSTACK
            0x73: self._op_if_dup,  # OP_IFDUP
            0x74: self._op_depth,  # OP_DEPTH
            0x75: self._op_drop,  # OP_DROP
            0x76: self._op_dup,  # OP_DUP
            0x77: self._op_nip,  # OP_NIP
            0x78: self._op_over,  # OP_OVER
            0x79: self._op_pick,  # OP_PICK
            0x7a: self._op_roll,  # OP_ROLL
            0x7b: self._op_rot,  # OP_ROT
            0x7c: self._op_swap,  # OP_SWAP
            0x7d: self._op_tuck,  # OP_TUCK
            0x6d: self._op_2drop,  # OP_2DROP
            0x6e: self._op_2dup,  # OP_2DUP
            0x6f: self._op_3dup,  # OP_3DUP
            0x70: self._op_2over,  # OP_2OVER
            0x71: self._op_2rot,  # OP_2ROT
            0x72: self._op_2swap,  # OP_2SWAP

            # Bitwise logic
            0x83: None,  # self._op_equal,  # OP_EQUAL
            0x84: None,  # self._op_equal_verify,  # OP_EQUALVERIFY

            # Arithmetic
            0x93: None,  # self._op_add,  # OP_ADD
            0x94: None,  # self._op_sub,  # OP_SUB
            0x95: None,  # self._op_mul,  # OP_MUL
            0x96: None,  # self._op_div,  # OP_DIV
            0x97: None,  # self._op_mod,  # OP_MOD
            0x9a: None,  # self._op_booland,  # OP_BOOLAND
            0x9b: None,  # self._op_boolor,  # OP_BOOLOR
            0x9c: self._op_numeq,  # OP_NUMEQUAL
            0x9d: self._op_numeq_verify,  # OP_NUMEQUALVERIFY
            0x9e: None,  # self._op_numneq,  # OP_NUMNOTEQUAL
            0x9f: None,  # self._op_lt,  # OP_LESSTHAN
            0xa0: None,  # self._op_gt,  # OP_GREATERTHAN
            0xa1: None,  # self._op_leq,  # OP_LESSTHANOREQUAL
            0xa2: None,  # self._op_geq,  # OP_GREATERTHANOREQUAL
            0xa3: None,  # self._op_min,  # OP_MIN
            0xa4: None,  # self._op_max,  # OP_MAX
            0xa5: None,  # self._op_within,  # OP_WITHIN

            # Crypto
            0xa6: None,  # self._op_ripemd160,  # OP_RIPEMD160
            0xa7: None,  # self._op_sha1,  # OP_SHA1
            0xa8: None,  # self._op_sha256,  # OP_SHA256
            0xa9: None,  # self._op_hash160,  # OP_HASH160
            0xaa: None,  # self._op_hash256,  # OP_HASH256
            0xac: None,  # self._op_checksig,  # OP_CHECKSIG
        }

    def clear_stacks(self):
        """
        Will remove all elements from main and alt stack. CLears ASM instructions. Used in testing
        """
        self.stack.clear()
        self.altstack.clear()
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

        # Control flow tracking
        if_stack = []
        execution_enabled = True

        # Main loop
        while True:
            opcode = stream.read(1)
            if not opcode:
                # End of script - check if all IFs are properly closed
                if if_stack:
                    raise ValueError("Unbalanced IF/ENDIF in script")
                break

            opcode_int = int.from_bytes(opcode, "big")
            logger.debug(f"OPCODE HEX: {opcode.hex()}")

            # Handle flow control opcodes
            if opcode_int in (0x63, 0x64, 0x67, 0x68):  # OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF
                handler = self.op_handlers.get(opcode_int)
                if handler:
                    # Call the flow control handler which updates if_stack and execution_enabled
                    if not handler(if_stack, execution_enabled):
                        return False
                    continue

            # Skip execution if disabled by flow control
            if not execution_enabled and opcode_int not in (0x67, 0x68):  # Skip unless OP_ELSE or OP_ENDIF
                continue

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
                    # Special handling for OP_VERIFY and OP_RETURN
                    if opcode_int == 0x69:  # OP_VERIFY
                        if not handler():
                            return False
                    elif opcode_int == 0x6a:  # OP_RETURN
                        handler()
                        return False
                    else:
                        handler()
                else:
                    logger.debug(f"Unrecognized or invalid OP code: {opcode_int:02x}")
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
            if self.stack.top in self.BTCZero:
                self._asm_log("Script failed validation: Zero value")
                return False
            self._asm_log("Script passes validation")
            return True
        else:
            self._asm_log("Script failed validation: Stack height > 1")
            return False

    # --- OP_CODE FUNCTIONS --- #

    def _op_true(self):
        self.stack.push(BTCNum(1).bytes)

    def _op_false(self):
        """OP_0 or OP_FALSE - Push empty bytes onto the stack"""
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

    def _op_1negate(self):
        """OP_1NEGATE - Push -1 onto the stack"""
        self.stack.push(BTCNum(-1).bytes)

    def _op_nop(self):
        pass

    def _op_if(self, if_stack, execution_enabled):
        """
        OP_IF implementation
        Marks an if block. The block will be executed if the top stack value is not False.
        """
        if execution_enabled:
            condition = self.stack.pop()
            result = condition not in self.BTCZero
            if_stack.append(("IF", result))
            return result
        else:
            if_stack.append(("IF", False))
            return True

    def _op_notif(self, if_stack, execution_enabled):
        """
        OP_NOTIF implementation
        Marks an if block. The block will be executed if the top stack value is False.
        """
        if execution_enabled:
            condition = self.stack.pop()
            result = condition in self.BTCZero
            if_stack.append(("NOTIF", result))
            return result
        else:
            if_stack.append(("NOTIF", False))
            return True

    def _op_else(self, if_stack, execution_enabled):
        """
        OP_ELSE implementation
        Marks an else block. The else block is executed if the if block is not executed.
        """
        if not if_stack:
            raise ValueError("OP_ELSE without matching OP_IF/OP_NOTIF")

        current_if = if_stack.pop()
        if_type, was_executed = current_if

        if if_type not in ("IF", "NOTIF"):
            raise ValueError(f"OP_ELSE after non-IF/NOTIF: {if_type}")

        if_stack.append(("ELSE", not was_executed))
        return not was_executed

    def _op_endif(self, if_stack, execution_enabled):
        """
        OP_ENDIF implementation
        Marks the end of an if/else block.
        """
        if not if_stack:
            raise ValueError("OP_ENDIF without matching OP_IF/OP_NOTIF/OP_ELSE")

        if_stack.pop()
        # Compute new execution_enabled based on remaining if_stack
        new_execution = all(executed for _, executed in if_stack)
        return new_execution

    def _op_verify(self):
        """OP_VERIFY - Verify the top element is truthy"""
        top = self.stack.pop()
        return False if top in self.BTCZero else True

    def _op_return(self):
        """OP_RETURN - Marks transaction as invalid"""
        return False

    def _op_to_altstack(self):
        self.altstack.push(self.stack.pop())

    def _op_from_altstack(self):
        self.stack.push(self.altstack.pop())

    def _op_if_dup(self):
        if self.stack.top not in self.BTCZero:
            self.stack.push(self.stack.top)

    def _op_depth(self):
        self.stack.push(BTCNum(self.stack.height).bytes)

    def _op_drop(self):
        self.stack.pop()

    def _op_dup(self):
        self.stack.push(self.stack.top)

    def _op_nip(self):
        """Removes the second-to-top stack item"""
        self.stack.remove_at_index(1)

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

    # def _op_booland(self):  # OP_BOOLAND | 0x9a
    #     """OP_BOOLAND - Boolean AND of two values"""
    #     self._op_bool_logic(lambda a, b: a and b)
    #
    # def _op_boolor(self):  # OP_BOOLOR | 0x9b
    #     """OP_BOOLOR - Boolean OR of two values"""
    #     self._op_bool_logic(lambda a, b: a or b)
    #
    def _op_numeq(self):  # OP_NUMEQUAL | 0x9c
        num1 = BTCNum(self.stack.pop()).value
        num2 = BTCNum(self.stack.pop()).value
        self._op_true() if num1 == num2 else self._op_false()

    def _op_numeq_verify(self):  # OP_NUMEQUALVERIFY | 0x9d
        self._op_numeq()
        return self._op_verify()

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

    # def _op_bool_logic(self, operation):
    #     """Generic handler for boolean logic operations
    #
    #     Args:
    #         operation: A function that takes two boolean arguments and returns a boolean
    #     """
    #     a_bytes, b_bytes = self.stack.pop_n(2)
    #
    #     a_true = a_bytes not in self.BTCZero
    #     b_true = b_bytes not in self.BTCZero
    #
    #     result = operation(a_true, b_true)
    #
    #     if result:
    #         self._op_true()
    #     else:
    #         self._op_false()


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
