"""
A module for the Stack and Script classes

The Script class contains a method to read and process a stack based on the op-codes in the stack.
"""

# --- IMPORTS --- #
from collections import deque
from typing import Any

from src.cipher import decompress_public_key, decode_transaction, decode_signature
from src.library.ecc import SECP256K1
from src.library.ecdsa import verify_signature
from src.library.hash_func import hash160, op_sha1, sha_256, ripemd160, hash256
from src.library.op_codes import OPCODES
from src.primitive import CompactSize, Endian
from src.tx import Transaction


# --- CLASSES --- #
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
    Each TxInput will have a scriptsig that will be used to unlock a scriptpubkey contained in a UTXO.
    We use the ScriptEngine inside the TxEngine for this purpose.
    """

    def __init__(self):
        self.opcode_dict = OPCODES
        self.main_stack = Stack()
        self.alt_stack = Stack()
        self.curve = SECP256K1()

    def clear_stacks(self):
        """
        Will remove all elements from main and alt stack
        """
        while self.main_stack.height > 0:
            self.main_stack.pop()
        while self.alt_stack.height > 0:
            self.alt_stack.pop()

    def parse_script(self, script: str, tx=None, input_index=None, utxo=None) -> bool:
        """
        We parse the script from left to right 1-byte at a time and act based on the corresponding op code
        """
        # Config
        i = 0
        length = len(script)

        def get_opcode(num_val: int):
            if 0 <= num_val <= 0x4b:
                return f"OP_PUSHBYTES_{num_val}"
            _op = [k for k, v in OPCODES.items() if v == num_val]
            if _op:
                return _op[0]
            return _op  # Empty list

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
                increment = self.stack_operator(script[i:])
            elif 0x7e <= byte <= 0x82:
                increment = self.strings(script[i:])
            elif 0x83 <= byte <= 0x8a:
                increment = self.bitwise_logic(script[i:])
            elif 0x8b <= byte <= 0xa5:
                increment = self.numeric(script[i:])
            elif 0xa6 <= byte <= 0xaf:
                increment = self.crypto(script[i:], tx, input_index, utxo)
            else:
                print("Other")
                increment = 2
            i += increment
        return True

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
                raise ValueError(f"OP_VERIFY command failed. Top of stack is false: {top}")
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
                item0 = self.main_stack.pop()
                item1 = self.main_stack.pop()
                item2 = self.main_stack.pop()
                for _ in range(2):
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

    def strings(self, script: str):
        op_code = int(script[:2], 16)
        current_index = 2

        if op_code in [0x7e, 0x7f, 0x80, 0x81]:
            # OP_CAT, OP_SUBSTR, OP_LEFT, OP_SIZE
            raise ValueError("Script contains disabled string OP_ codes")
        else:
            # OP_SIZE - push string length of top element to stack
            top_element = self.main_stack.top
            str_len = len(top_element) if isinstance(top_element, str) else len(str(top_element))
            self.main_stack.push(str_len)

        return current_index

    def bitwise_logic(self, script: str):
        op_code = int(script[:2], 16)
        current_index = 2

        if op_code in [0x83, 0x84, 0x85, 0x86]:
            # OP_INVERT, OP_AND, OP_OR, OP_XOR
            raise ValueError(f"Script contains disabled bitwise logic OP-code: {hex(op_code)}")
        elif op_code in [0x87, 0x88]:
            # OP_EQUAL - Pushes True to the stack if top 2 elements are equal, False otherwise
            item1 = self.main_stack.pop()
            item2 = self.main_stack.pop()
            self.main_stack.push(item1 == item2)

            # OP_EQUALVERIFY
            if op_code == 0x88:
                val = self.main_stack.pop()
                if not val:
                    raise ValueError("OP_EQUALVERIFY fails verification")

        return current_index

    def numeric(self, script: str):
        op_code = int(script[:2], 16)
        current_index = 2

        if op_code in [0x8d, 0x8e, 0x95, 0x96, 0x97, 0x98, 0x99]:
            # OP_2MUL, OP_2DIV, OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT
            raise ValueError(f"Script contains disabled numeric op-code: {hex(op_code)}")
        else:
            # Valid numeric op-code
            verify = False  # Flag for OP_NUMEQUALVERIFY
            v0 = self.main_stack.pop()
            match op_code:
                case 0x8b:  # OP_1ADD
                    val = v0 + 1
                case 0x8c:  # OP_1SUB
                    val = v0 - 1
                case 0x8f:  # OP_NEGATE
                    val = v0 * -1
                case 0x90:  # OP_ABS
                    val = -v0 if v0 < 0 else v0
                case 0x91:  # OP_NOT
                    val = (v0 + 1) % 2 if v0 in [0, 1] else 0
                case 0x92:  # OP_0NOTEQUAL
                    val = 1 if v0 != 0 else v0
                case _:
                    v1 = self.main_stack.pop()
                    match op_code:
                        case 0x93:  # OP_ADD
                            val = v0 + v1
                        case 0x94:  # OP_SUB
                            val = v0 - v1
                        case 0x9a:  # OP_BOOLAND
                            val = 1 if (v0 != 0 and v1 != 0) else 0
                        case 0x9b:  # OP_BOOLOR
                            val = 1 if (v0 != 0 or v1 != 0) else 0
                        case 0x9c | 0x9d:  # OP_NUMEQUAL
                            val = 1 if (v0 == v1) else 0
                            # OP_NUMEQUAL_VERIFY
                            if op_code == 0x9d:
                                verify = True
                                if val == 0:
                                    raise ValueError("Script failed OP_NUMEQUALVERIFY")
                        case 0x9e:  # OP_NUMNOTEQUAL
                            val = 1 if (v0 != v1) else 0
                        case 0x9f:  # OP_LESSTHAN
                            val = 1 if v0 < v1 else 0
                        case 0xa0:  # OP_GREATERTHAN
                            val = 1 if v0 > v1 else 0
                        case 0xa1:  # OP_LESSTHANOREQUAL
                            val = 1 if v0 <= v1 else 0
                        case 0xa2:  # OP_GREATERTHANOREQUAL
                            val = 1 if v0 >= v1 else 0
                        case 0xa3:  # OP_MIN
                            val = v0 if v0 < v1 else v1
                        case 0xa4:  # OP_MAX
                            val = v0 if v0 > v1 else v1
                        case 0xa5:  # OP_WITHIN
                            v2 = self.main_stack.pop()
                            val = 1 if v1 <= v0 < v2 else 0
            self.main_stack.push(val)
            if verify:
                self.main_stack.pop()
            return current_index

    def crypto(self, script: str, tx=None, input_index=None, utxo=None):
        op_code = int(script[:2], 16)
        current_index = 2

        v0 = self.main_stack.pop()
        if op_code == 0xa6:
            # OP_RIPEMD160
            val = ripemd160(v0)
        elif op_code == 0xa7:
            # OP_SHA1
            val = op_sha1(v0)
        elif op_code == 0xa8:
            # OP_SHA256
            val = sha_256(v0)
        elif op_code == 0xa9:
            # OP_HASH160
            val = hash160(v0)
        elif op_code == 0xaa:
            # OP_HASH256
            val = hash256(v0)
        elif op_code == 0xab:
            # OP_CODESEPARATOR
            print("OP_CODESEPARATOR")
        elif op_code in [0xac, 0xad]:
            # OP_CHECKSIG
            _cpk = v0  # Public key
            _sig = self.main_stack.pop()  # Signature

            # get public key point
            _pk = decompress_public_key(_cpk)

            # extract hashtype from signature
            _hashtype = _sig[-1:]

            # get sig tuple
            r, s = decode_signature(_sig)

            # create tx for verification
            txcopy = decode_transaction(tx.hex)
            for i in txcopy.inputs:
                i.scriptsig = bytes()
                i.scriptsig_size = CompactSize(0)
            signed_input = txcopy.inputs[input_index]
            signed_input.scriptsig = utxo.scriptpubkey
            signed_input.scriptsig_size = CompactSize(len(utxo.scriptpubkey))
            txcopy.inputs[input_index] = signed_input

            hash_string = hash256(txcopy.hex + Endian(int(_hashtype, 16), length=Transaction.SIGHASH_BYTES).hex)

            val = verify_signature((r, s), hash_string, _pk)

            # OP_CHECKSIGVERIFY
            if not val:
                raise ValueError("Script failed OP_CHECKSIGVERIFY")
        elif op_code == 0xa:
            # OP_CHECKMULTISIG
            print("OP_CHECKMULTISIG")
            val = 0
        elif op_code == 0xab:
            # OP_CHECKMULTISIGVERIFY
            print("OP CHECKMULTISIGVERIFY")
            val = 0
        else:
            val = 0

        self.main_stack.push(val)
        return current_index

    def other(self, script: str):
        op_code = int(script[:2], 16)
        current_index = 2

        if op_code == 0xb0:
            # OP_NOP1
            pass
        elif op_code == 0xb1:
            # OP_CHECKLOCKTIMEVERIFY
            v0 = self.main_stack.pop()
            print("OP_CHECKLOCKTIMEVERIFY")
            self.main_stack.push(v0)
        elif op_code == 0xb2:
            # OP_CHECKSEQUENCEVERIFY
            v0 = self.main_stack.pop()
            print("OP_CHECKSEQUENCEVERIFY")
            self.main_stack.push(v0)
        elif op_code in [range(0xb3, 0xb9)]:
            # OP_NOP4 -- OP_NOP10
            pass
        elif op_code == 0xba:
            # OP_CHECKSIGADD
            print("OP_CHECKSIGADD")
        else:
            raise ValueError(f"Script used invalid code: {hex(op_code)}")

        return current_index


# -- TESTING
if __name__ == "__main__":
    engine = ScriptEngine()
    tx_id = hash256("DATA")

    script = "515194"
    engine.parse_script(script)
    print(engine.main_stack.stack)
