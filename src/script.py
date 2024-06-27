"""
A module for the Stack and Script classes

The Script class contains a method to read and process a stack based on the op-codes in the stack.

# TODO:
    - Implement the IF/ELSE control flow logic
"""

# --- IMPORTS --- #
import logging
import sys
from collections import deque
from typing import Any

from src.op_codes import OPCODES

# --- LOGGING --- #
log_level = logging.DEBUG
logger = logging.getLogger(__name__)
logger.setLevel(log_level)
handler = logging.StreamHandler(stream=sys.stdout)
logger.addHandler(handler)


# --- CLASSES --- #
class Stack:
    """
    We use the deque class from the collections model to create a Stack class. This will be used in Script class for
    a stack of bytes. The stack can be viewed as a list of data running from left to right, where the left most
    element (i.e. the element indexed at 0) is the TOP of the stack.
    """

    def __init__(self):
        self.stack = deque()

    def push(self, element: Any):
        self.stack.appendleft(element)

    def pop(self):
        try:
            return_val = self.stack.popleft()
        except IndexError:
            raise IndexError("Popped from empty stack")
        return return_val

    @property
    def top(self):
        try:
            val = self.stack[0]
        except IndexError:
            raise IndexError("Empty stack")
        return val

    @property
    def height(self):
        return len(self.stack)

    def clear_stack(self):
        while True:
            try:
                self.stack.pop()
            except IndexError:
                break


class ScriptEngine:
    """
    There are two steps to script:
        1) Decoding string into hex
        2) Evaluating hex string as a whole
    """

    def __init__(self):
        self.opcode_dict = OPCODES
        self.main_stack = Stack()
        self.alt_stack = Stack()

    def parse_script(self, script: str):
        """
        We parse the script from left to right 1-byte at a time and act based on the corresponding op code
        """
        # Config
        i = 0
        length = len(script)

        # Parse
        while i < length:
            # Integer value
            byte = int(script[i: i + 2], 16)

            # Push data
            if 0 <= byte <= 96:
                increment = self.push_data(script[i:])
            elif 0x61 <= byte <= 0x6a:
                increment = self.control_flow(script[i:])
            elif 0x6b <= byte <= 0x7d:
                print("Stack operators")
                increment = self.stack_operator(script[i:])
            elif 0x7e <= byte <= 0x82:
                print("Strings")
                increment = 2
            elif 0x83 <= byte <= 0x8a:
                print("Bitwise logic")
                increment = 2
            elif 0x8b <= byte <= 0xa5:
                print("Numeric")
                increment = 2
            elif 0xa6 <= byte <= 0xaf:
                print("Cryptography")
                increment = 2
            else:
                print("Other")
                increment = 2
            i += increment

    def push_data(self, script: str):
        op_code = int(script[:2], 16)
        current_index = 2
        if op_code == 0:
            # Push empty byte string to stack
            op_bytes = None
        elif 0 < op_code <= 0x4b:
            # Push op_code number of bytes
            op_bytes = script[current_index:current_index + 2 * op_code]
            current_index += 2 * op_code
        elif 0x4c <= op_code <= 0x4e:
            # Push next 1/2/4 bytes to stack
            match op_code:
                case 0x4c:
                    increment = 2
                case 0x4d:
                    increment = 4
                case _:
                    increment = 8
            byte_length = int(script[current_index:current_index + increment], 16)
            op_bytes = script[current_index:current_index + 2 * byte_length]
            current_index += increment
        elif op_code == 0x4f:
            # Push -1 to stack
            op_bytes = -1
        elif op_code == 0x50:
            # Fail script immediately
            raise ValueError("Reached terminate code in script")
        else:
            # Otherwise push one of 1 -- 16 onto the stack
            op_bytes = op_code - 0x50

        self.main_stack.push(op_bytes)
        return current_index

    def control_flow(self, script: str):
        op_code = int(script[:2], 16)
        current_index = 2

        if op_code == 0x61:
            # OP_NOP - No operation
            pass
        elif op_code in [0x62, 0x65, 0x66, 0x6a]:
            # OP_VER, OP_VERIF, OP_VERNOTIF, OP_RETURN
            raise ValueError(f"Reached {op_code} in script")
        elif op_code == 0x63:
            print("IF")
        elif op_code == 0x64:
            print("NOTIF")
        elif op_code == 0x67:
            print("ELSE")
        elif op_code == 0x68:
            print("ENDIF")
        elif op_code == 0x69:
            # OP_VERIFY
            top = self.main_stack.pop()
            if not top:
                raise ValueError(f"OP_VERIFY command failed. Top of stack is empty: {top}")
        return current_index

    def stack_operator(self, script: str):
        STACK_ERROR = "Insufficient elements in the stack."
        op_code = int(script[:2], 16)
        current_index = 2
        try:
            if op_code == 0x6b:
                # OP_TOALTSTACK
                item = self.main_stack.pop()
                self.alt_stack.push(item)
            elif op_code == 0x6c:
                # OP_FROMALTSTACK
                item = self.alt_stack.pop()
                self.main_stack.push(item)
            elif op_code == 0x6d:
                # OP_2DROP - discard 2 items
                self.main_stack.pop()
                self.main_stack.pop()
            elif op_code == 0x6e:
                # OP_2DUP
                item1 = self.main_stack.stack[1]  # Deeper in the stack
                item0 = self.main_stack.top
                self.main_stack.push(item1)  # Push buried element
                self.main_stack.push(item0)  # Push top element
            elif op_code == 0x6f:
                # OP_3DUP
                item2 = self.main_stack.stack[2]
                item1 = self.main_stack.stack[1]
                item0 = self.main_stack.top
                self.main_stack.push(item2)
                self.main_stack.push(item1)
                self.main_stack.push(item0)
            elif op_code == 0x70:
                # OP_2OVER - copies pair of items 2 spaces back to the front
                # e.g: if stack = [ a, b, c, d] (a=top, d = bottom) - then OP_2OVER(stack) = [c, d, a, b, c, d]
                item3 = self.main_stack.stack[3]
                item2 = self.main_stack.stack[2]
                self.main_stack.push(item3)
                self.main_stack.push(item2)
            elif op_code == 0x71:
                # OP_2ROT - The fifth and sixth items back are moved to the top of the stack.
                var1 = [self.main_stack.pop() for _ in range(4)][::-1]  # Pop top 4 elements, save in reverse order
                var2 = [self.main_stack.pop() for _ in range(2)][::-1]  # Pop top 2 elements, save in reverse order
                # Push to stack
                for v1 in var1:
                    self.main_stack.push(v1)
                for v2 in var2:
                    self.main_stack.push(v2)
            elif op_code == 0x72:
                # OP_2SWAP - Swaps the top two pairs of items.
                var1 = [self.main_stack.pop() for _ in range(2)][::-1]
                var2 = [self.main_stack.pop() for _ in range(2)][::-1]
                # Push to stack
                for v1 in var1:
                    self.main_stack.push(v1)
                for v2 in var2:
                    self.main_stack.push(v2)
            elif op_code == 0x73:
                # OP_IFDUP - If the top stack value is not 0, duplicate it.
                top = self.main_stack.top
                if top and top != 0:
                    self.main_stack.push(top)
            elif op_code == 0x74:
                # OP_DEPTH - Puts the number of stack items onto the stack.
                depth = len(self.main_stack.stack)
                self.main_stack.push(depth)
            elif op_code == 0x75:
                # OP_DROP - Removes top stack item
                self.main_stack.pop()
            elif op_code == 0x76:
                # OP_DUP - Duplicate top stack item
                top = self.main_stack.top
                self.main_stack.push(top)
            elif op_code == 0x77:
                # OP_NIP - Removes the second-to-top stack item
                top = self.main_stack.pop()
                self.main_stack.pop()  # Drop item
                self.main_stack.push(top)
            elif op_code == 0x78:
                # OP_OVER - Copies the second-to-top stack item to the top.
                top = self.main_stack.pop()
                second_to_top = self.main_stack.top
                self.main_stack.push(top)
                self.main_stack.push(second_to_top)
            elif op_code == 0x79:
                # OP_PICK - The item n back in the stack is copied to the top.
                n = int(script[current_index:current_index + 2], 16)
                current_index += 2

                var1 = [self.main_stack.pop() for _ in range(n)][::-1]  # pops top n-1 items
                nth_item = self.main_stack.top
                for v1 in var1:
                    self.main_stack.push(v1)
                self.main_stack.push(nth_item)
            elif op_code == 0x7a:
                # OP_ROLL - The item n back in the stack is moved to the top.
                n = int(script[current_index:current_index + 2], 16)
                current_index += 2
                var1 = [self.main_stack.pop() for _ in range(n)][::-1]  # pops top n-1 items, saved from bottom to top
                var2 = self.main_stack.pop()  # nth item
                for v1 in var1:
                    self.main_stack.push(v1)
                self.main_stack.push(var2)
            elif op_code == 0x7b:
                # OP_ROT - The 3rd item down the stack is moved to the top.
                var1 = [self.main_stack.pop() for _ in range(2)][::-1]
                var2 = self.main_stack.pop()
                for v1 in var1:
                    self.main_stack.push(v1)
                self.main_stack.push(var2)
            elif op_code == 0x7c:
                # OP_SWAP - The top two items on the stack are swapped.
                var1 = self.main_stack.pop()
                var2 = self.main_stack.pop()
                self.main_stack.push(var1)
                self.main_stack.push(var2)
            elif op_code == 0x7d:
                # OP_TUCK - The item at the top of the stack is copied and inserted before the second-to-top item.
                var1 = self.main_stack.pop()
                var2 = self.main_stack.pop()
                self.main_stack.push(var1)
                self.main_stack.push(var2)
                self.main_stack.push(var1)

        except IndexError:
            raise IndexError(STACK_ERROR)

        return current_index


from src.encoder_lib import hash256

# -- TESTING
if __name__ == "__main__":
    engine = ScriptEngine()
    tx_id = hash256("DATA")

    script = "51527d"
    engine.parse_script(script)
    print(engine.main_stack.stack)
