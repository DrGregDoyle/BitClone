"""
The ScriptEngine class
"""
from io import BytesIO
from typing import Callable, Dict

from src.library.Script.op_codes import OPCODES
from src.library.Script.stack import BTCNum, BTCStack
from src.library.data_handling import check_hex, check_length
from src.library.ecc import secp256k1
from src.logger import get_logger

logger = get_logger(__name__)


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
        self.stack = BTCStack()
        self.altstack = BTCStack()
        self.asm = []  # List of ASM instructions when evaluating script

        self.op_handlers = self._initialize_op_handlers()

    def _initialize_op_handlers(self) -> Dict[int, Callable]:
        return {
            # Constants
            0x00: self._op_false,  # OP_0, OP_FALSE
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
            0x73: self._op_ifdup,  # OP_IFDUP
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
            0x82: self._op_size,  # OP_SIZE

            # Bitwise logic
            0x87: self._op_equal,  # OP_EQUAL
            0x88: self._op_equal_verify,  # OP_EQUALVERIFY

            # Arithmetic
            0x8b: self._op_1add,  # OP_1ADD
            0x8c: self._op_1sub,  # OP_1SUB
            0x8f: self._op_negate,  # OP_NEGATE
            0x90: self._op_abs,  # OP_ABS
            0x91: self._op_not,  # OP_NOT
            0x92: self._op_0notequal,  # OP_0NOTEQUAL
            0x93: self._op_add,  # OP_ADD
            0x94: self._op_sub,  # OP_SUB
            # 0x95:  self._op_mul,  # OP_MUL
            # 0x96:  self._op_div,  # OP_DIV
            # 0x97: self._op_mod,  # OP_MOD
            0x9a: self._op_booland,  # OP_BOOLAND
            0x9b: self._op_boolor,  # OP_BOOLOR
            0x9c: self._op_numeq,  # OP_NUMEQUAL
            0x9d: self._op_numeq_verify,  # OP_NUMEQUALVERIFY
            0x9e: self._op_numneq,  # OP_NUMNOTEQUAL
            0x9f: self._op_lt,  # OP_LESSTHAN
            0xa0: self._op_gt,  # OP_GREATERTHAN
            0xa1: self._op_leq,  # OP_LESSTHANOREQUAL
            0xa2: self._op_geq,  # OP_GREATERTHANOREQUAL
            0xa3: self._op_min,  # OP_MIN
            0xa4: self._op_max,  # OP_MAX
            0xa5: self._op_within,  # OP_WITHIN

            # Crypto
            0xa6: self._op_ripemd160,  # OP_RIPEMD160
            0xa7: self._op_sha1,  # OP_SHA1
            0xa8: self._op_sha256,  # OP_SHA256
            0xa9: self._op_hash160,  # OP_HASH160
            0xaa: self._op_hash256,  # OP_HASH256
            0xac: self._op_checksig,  # OP_CHECKSIG
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
        valid_script = True

        # Main loop
        while valid_script:
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
                        valid_script = False
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
                            self._asm_log("Failed OP_VERIFY")
                            valid_script = False
                    elif opcode_int == 0x6a:  # OP_RETURN
                        self._asm_log("Processing OP_RETURN")
                        handler()
                        valid_script = False
                    else:
                        handler()
                else:
                    logger.debug(f"Unrecognized or invalid OP code: {opcode_int:02x}")
                    valid_script = False

        # Validate stack
        return self._validate_stack() if valid_script else False

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

    def _op_ifdup(self):
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
        self.stack.nip()

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
        roll_index = BTCNum.from_bytes(self.stack.pop())
        self.stack.roll(roll_index.value)

    def _op_rot(self):
        self.stack.rot()

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

    def _op_size(self):
        # Check for empty stack
        top_element = self.stack.top if self.stack.height > 0 else b''
        if top_element in self.BTCZero:
            self.stack.push(BTCNum(0).bytes)
        else:
            self.stack.push(BTCNum(len(top_element)).bytes)

    def _op_equal(self):
        items = self.stack.pop_n(2)
        if items[0] == items[1]:
            self._op_true()
        else:
            self._op_false()

    def _op_equal_verify(self):
        self._op_equal()
        return self._op_verify()

    def _op_1add(self):
        """
        OP_1ADD, 0x8b - 1 is added to the input.
        """
        item = self.stack.pop()
        item_plus1 = BTCNum.from_bytes(item) + BTCNum(1)
        self.stack.push(item_plus1.bytes)

    def _op_1sub(self):
        """
        OP_1SUB, 0x8c - 1 is subtracted from the input.
        """
        item = self.stack.pop()
        item_plus1 = BTCNum.from_bytes(item) - BTCNum(1)
        self.stack.push(item_plus1.bytes)

    def _op_negate(self):
        """
        OP_NEGATE, 0x8f - The sign of the input is flipped.
        """
        stack_num = BTCNum.from_bytes(self.stack.pop())
        neg_stack_num = -stack_num
        self.stack.push(neg_stack_num.bytes)

    def _op_abs(self):
        """
        OP_ABS, 0x90 - The input is made positive.
        """
        stack_num = BTCNum.from_bytes(self.stack.pop())
        self.stack.push(abs(stack_num).bytes)

    def _op_not(self):
        """
        OP_NOT, 0x91 - If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
        """
        item = self.stack.pop()
        self._op_true() if item == b'' else self._op_false()

    def _op_0notequal(self):
        """
        OP_0NOTEQUAL, 0x92 - Returns 0 if the input is 0. 1 otherwise.
        """
        pass

    def _op_add(self):
        """
        OP_ADD, 0x93 - a is added to b.
        """
        pass

    def _op_sub(self):
        """
        OP_SUB, 0x94 - b is subtracted from a.
        """
        pass

    def _op_booland(self):
        """
        OP_BOOLAND, 0x9a - If both a and b are not 0, the output is 1. Otherwise 0.
        """
        pass

    def _op_boolor(self):
        """
        OP_BOOLOR, 0x9b - If a or b is not 0, the output is 1. Otherwise 0.
        """
        pass

    def _op_numeq(self):
        """
        OP_NUMEQUAL, 0x9c - Returns 1 if the numbers are equal, 0 otherwise.
        """
        pass

    def _op_numeq_verify(self):
        """
        OP_NUMEQUALVERIFY, 0x9d - Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
        """
        pass

    def _op_numneq(self):
        """
        OP_NUMNOTEQUAL, 0x9e - Returns 1 if the numbers are not equal, 0 otherwise.
        """
        pass

    def _op_lt(self):
        """
        OP_LESSTHAN, 0x9f - Returns 1 if a is less than b, 0 otherwise.
        """
        pass

    def _op_gt(self):
        """
        OP_GREATERTHAN, 0xa0 - Returns 1 if a is greater than b, 0 otherwise.
        """
        pass

    def _op_leq(self):
        """
        OP_LESSTHANOREQUAL, 0xa1 - Returns 1 if a is less than or equal to b, 0 otherwise.
        """
        pass

    def _op_geq(self):
        """
        OP_GREATERTHANOREQUAL, 0xa2 - Returns 1 if a is greater than or equal to b, 0 otherwise.
        """
        pass

    def _op_min(self):
        """
        OP_MIN, 0xa3 - Returns the smaller of a and b.
        """
        pass

    def _op_max(self):
        """
        OP_MAX, 0xa4 - Returns the larger of a and b.
        """
        pass

    def _op_within(self):
        """
        OP_WITHIN, 0xa5 - Returns 1 if x is within the specified range (left-inclusive), 0 otherwise.
        """
        pass

    def _op_ripemd160(self):
        """
        OP_RIPEMD160, 0xa6 - The input is hashed using RIPEMD-160.
        """
        pass

    def _op_sha1(self):
        """
        OP_SHA1, 0xa7 - The input is hashed using SHA-1.
        """
        pass

    def _op_sha256(self):
        """
        OP_SHA256, 0xa8 - The input is hashed using SHA-256.
        """
        pass

    def _op_hash160(self):
        """
        OP_HASH160, 0xa9 - The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
        """
        pass

    def _op_hash256(self):
        """
        OP_HASH256, 0xaa - The input is hashed two times with SHA-256.
        """
        pass

    def _op_codeseparator(self):
        """
        OP_CODESEPARATOR, 0xab - All of the signature checking words will only match signatures to the data after the
        most recently-executed OP_CODESEPARATOR.
        """
        pass

    def _op_checksig(self):
        """
        OP_CHECKSIG, 0xac - The entire transaction's outputs, inputs, and script (from the most recently-executed
        OP_CODESEPARATOR to the end) are hashed. The signature used by OP_CHECKSIG must be a valid signature for this
        hash and public key.
        """
        pass

    def _op_checksigverify(self):
        """
        OP_CHECKSIGVERIFY, 0xad - Same as OP_CHECKSIG, but OP_VERIFY is executed afterward.
        """
        pass

    def _op_checkmultisig(self):
        """
        OP_CHECKMULTISIG, 0xae - Compares the first signature against each public key until it finds an ECDSA match.
        Starting with the subsequent public key, it compares the second signature against each remaining public key
        until it finds an ECDSA match. The process is repeated until all signatures have been checked or not enough
        public keys remain to produce a successful result.
        """
        pass

    def _op_checkmultisigverify(self):
        """
        OP_CHECKMULTISIGVERIFY, 0xaf - Same as OP_CHECKMULTISIG, but OP_VERIFY is executed afterward.
        """
        pass

    def _op_nop1(self):
        """
        OP_NOP1, 0xb0 - Does nothing.
        """
        pass

    def _op_checklocktimeverify(self):
        """
        OP_CHECKLOCKTIMEVERIFY, 0xb1 - Marks transaction as invalid if the top stack item is greater than the
        transaction's nLockTime field.
        """
        pass

    def _op_checksequenceverify(self):
        """
        OP_CHECKSEQUENCEVERIFY, 0xb2 - Marks transaction as invalid if the relative lock time of the input (
        enforced by
        BIP 68 with nSequence) is not equal to or longer than the value of the top stack item.
        """
        pass

    def _op_nop4(self):
        """
        OP_NOP4, 0xb3 - Does nothing.
        """
        pass

    def _op_nop5(self):
        """
        OP_NOP5, 0xb4 - Does nothing.
        """
        pass

    def _op_nop6(self):
        """
        OP_NOP6, 0xb5 - Does nothing.
        """
        pass

    def _op_nop7(self):
        """
        OP_NOP7, 0xb6 - Does nothing.
        """
        pass

    def _op_nop8(self):
        """
        OP_NOP8, 0xb7 - Does nothing.
        """
        pass

    def _op_nop9(self):
        """
        OP_NOP9, 0xb8 - Does nothing.
        """
        pass

    def _op_nop10(self):
        """
        OP_NOP10, 0xb9 - Does nothing.
        """
        pass

    def _op_invalidopcode(self):
        """
        OP_INVALIDOPCODE, 0xff - Represents an invalid opcode.
        """
        pass

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


# --- TESTING

if __name__ == "__main__":
    test_script_hex = "5191"
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
