"""
A module for the Stack and Script classes

The Script class contains a method to read and process a stack based on the op-codes in the stack.

"""

# --- IMPORTS --- #
import logging
import sys
from collections import deque
from typing import Any

from op_codes import OPCODES

# --- LOGGING --- #
log_level = logging.DEBUG
logger = logging.getLogger(__name__)
logger.setLevel(log_level)
handler = logging.StreamHandler(stream=sys.stdout)
logger.addHandler(handler)


# --- CLASSES --- #
class Stack:
    """
    We use the deque class from the collections model to create a Stack class.
    This will be used in Script class for a stack of bytes.
    """

    def __init__(self):
        self.stack = deque()

    def push(self, element: Any):
        self.stack.append(element)

    def pop(self):
        try:
            return_val = self.stack.pop()
        except IndexError:
            logger.debug("Popped from empty stack")
            return_val = None
        return return_val


class Script:
    """
    There are two steps to script:
        1) Decoding string into hex
        2) Evaluating hex string as a whole
    """
    BYTE_SIZE = 4

    def __init__(self):
        self.opcode_dict = OPCODES
        self.main_stack = Stack()
        self.alt_stack = Stack()

    def decode(self, my_script: str):
        """
        Given a script with op-codes and data in hex format, we decode the string to a sequence of hex characters
        """
        # Divide script by spaces
        script_list = my_script.split(" ")
        hex_script = ""

        # For each word, either read in as hex or decode op-code
        for word in script_list:
            if word[:3] == "OP_":
                code_value = self.opcode_dict.get(word)
                hex_script += format(code_value, "02x").upper()
            else:
                # TODO: Check word is in hex
                hex_script += word

        return hex_script

    def execute(self, scriptSig: list, scriptPubKey: str):
        """
        We execute the script according to the hex script. The elements of scriptSig will first be added to the
        stack, then the hex script will be evaluated.

        The scriptSig comes from the input, and the scriptPubKey is in the referenced output.
        """
        # Add script
        sig, pubKey = scriptSig
        self.main_stack.push(sig)
        self.main_stack.push(pubKey)

        # Evaluate scriptPubKey
        

# --- TESTING --- #
if __name__ == "__main__":
    s1 = Script()
    my_script = "<sig> <pubKey> OP_DUP OP_HASH160 OP_FALSE <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG"
    print(s1.decode(my_script))
