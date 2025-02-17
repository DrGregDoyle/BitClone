"""
Classes for executing and verifying scripts
"""
from collections import deque
from io import BytesIO
from typing import Any

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


class ScriptEngine:
    """
    A class for evaluating script
    """

    def __init__(self):
        """
        Setup stack
        """
        self.op_codes = OPCODES
        self.curve = secp256k1()
        self.stack = Stack()
        self.alt_stack = Stack()
        self.asm = []  # List of ASM instructions when evaluating script

    def clear_stacks(self):
        """
        Will remove all elements from main and alt stack. CLears ASM instructions
        """
        while self.stack.height > 0:
            self.stack.pop()
        while self.alt_stack.height > 0:
            self.alt_stack.pop()
        self.asm = []

    def eval_script_from_hex(self, hex_script: hex):
        clean_hex_script = check_hex(hex_script)
        bytes_eval = self.eval_script(bytes.fromhex(clean_hex_script))
        return bytes_eval

    def eval_script(self, script: bytes) -> bool:
        """
        Evaluates the script - returns True/False based on results of main stack
        """
        # Get script as byte strem
        if not isinstance(script, (bytes, BytesIO)):
            raise ValueError(f"Expected byte data stream, received {type(script)}")

        stream = BytesIO(script) if isinstance(script, bytes) else script

        while True:
            opcode = stream.read(1)
            if not opcode:
                break  # End of script

            opcode_int = int.from_bytes(opcode, "big")

            # Check for PushData
            if 0x00 < opcode_int < 0x4c:
                opcode_asm = f"OP_PUSHBYTES_{opcode_int}"
                self.asm.append(opcode_asm)
                self._push_data(stream, opcode_int)
            else:
                opcode_asm = OPCODES[opcode_int]

            logger.info(f"OPCODE: {opcode_asm}")

        return True

    def _push_data(self, stream: BytesIO, byte_length: int):
        """
        OpCode triggered data push
        """
        data = stream.read(byte_length)
        check_length(data, byte_length, "pushdata")
        hex_data = data.hex()
        self.stack.push(data)
        self.asm.append(hex_data)  # Hex instructions for readability
        logger.info(f"Pushed data with length {byte_length}")
        logger.info(f"Pushed data: {hex_data}")


# --- TESTING

if __name__ == "__main__":
    test_hex_script = "410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac"
    engine = ScriptEngine()
    engine.eval_script_from_hex(test_hex_script)
