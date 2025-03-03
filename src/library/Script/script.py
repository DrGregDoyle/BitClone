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


# def op_0():
#     """
#     OP_0, 0x00 - An empty array of bytes is pushed onto the stack.
#     """
#     pass
#
# def op_pushdata1():
#     """
#     OP_PUSHDATA1, 0x4c - The next byte contains the number of bytes to be pushed onto the stack.
#     """
#     pass
#
# def op_pushdata2():
#     """
#     OP_PUSHDATA2, 0x4d - The next two bytes contain the number of bytes to be pushed onto the stack.
#     """
#     pass
#
# def op_pushdata4():
#     """
#     OP_PUSHDATA4, 0x4e - The next four bytes contain the number of bytes to be pushed onto the stack.
#     """
#     pass
#
# def op_1negate():
#     """
#     OP_1NEGATE, 0x4f - The number -1 is pushed onto the stack.
#     """
#     pass
#
# def op_1():
#     """
#     OP_1, 0x51 - The number 1 is pushed onto the stack.
#     """
#     pass
#
# def op_2():
#     """
#     OP_2, 0x52 - The number 2 is pushed onto the stack.
#     """
#     pass
#
# def op_3():
#     """
#     OP_3, 0x53 - The number 3 is pushed onto the stack.
#     """
#     pass
#
# def op_4():
#     """
#     OP_4, 0x54 - The number 4 is pushed onto the stack.
#     """
#     pass
#
# def op_5():
#     """
#     OP_5, 0x55 - The number 5 is pushed onto the stack.
#     """
#     pass
#
# def op_6():
#     """
#     OP_6, 0x56 - The number 6 is pushed onto the stack.
#     """
#     pass
#
# def op_7():
#     """
#     OP_7, 0x57 - The number 7 is pushed onto the stack.
#     """
#     pass
#
# def op_8():
#     """
#     OP_8, 0x58 - The number 8 is pushed onto the stack.
#     """
#     pass
#
# def op_9():
#     """
#     OP_9, 0x59 - The number 9 is pushed onto the stack.
#     """
#     pass
#
# def op_10():
#     """
#     OP_10, 0x5a - The number 10 is pushed onto the stack.
#     """
#     pass
#
# def op_11():
#     """
#     OP_11, 0x5b - The number 11 is pushed onto the stack.
#     """
#     pass
#
# def op_12():
#     """
#     OP_12, 0x5c - The number 12 is pushed onto the stack.
#     """
#     pass
#
# def op_13():
#     """
#     OP_13, 0x5d - The number 13 is pushed onto the stack.
#     """
#     pass
#
# def op_14():
#     """
#     OP_14, 0x5e - The number 14 is pushed onto the stack.
#     """
#     pass
#
# def op_15():
#     """
#     OP_15, 0x5f - The number 15 is pushed onto the stack.
#     """
#     pass
#
# def op_16():
#     """
#     OP_16, 0x60 - The number 16 is pushed onto the stack.
#     """
#     pass
#
# def op_nop():
#     """
#     OP_NOP, 0x61 - Does nothing.
#     """
#     pass
#
# def op_if():
#     """
#     OP_IF, 0x63 - If the top stack value is not 0, the statements are executed.
#     """
#     pass
#
# def op_notif():
#     """
#     OP_NOTIF, 0x64 - If the top stack value is 0, the statements are executed.
#     """
#     pass
#
# def op_else():
#     """
#     OP_ELSE, 0x67 - If the preceding OP_IF or OP_NOTIF was not executed, these statements are.
#     """
#     pass
#
# def op_endif():
#     """
#     OP_ENDIF, 0x68 - Ends an if/else block.
#     """
#     pass
#
# def op_verify():
#     """
#     OP_VERIFY, 0x69 - Marks transaction as invalid if top stack value is not true.
#     """
#     pass
#
# def op_return():
#     """
#     OP_RETURN, 0x6a - Marks transaction as invalid.
#     """
#     pass
#
# def op_toaltstack():
#     """
#     OP_TOALTSTACK, 0x6b - Puts the input onto the top of the alt stack. Removes it from the main stack.
#     """
#     pass
#
# def op_fromaltstack():
#     """
#     OP_FROMALTSTACK, 0x6c - Puts the input onto the top of the main stack. Removes it from the alt stack.
#     """
#     pass
#
# def op_2drop():
#     """
#     OP_2DROP, 0x6d - Removes the top two stack items.
#     """
#     pass
#
# def op_2dup():
#     """
#     OP_2DUP, 0x6e - Duplicates the top two stack items.
#     """
#     pass
#
# def op_3dup():
#     """
#     OP_3DUP, 0x6f - Duplicates the top three stack items.
#     """
#     pass
#
# def op_2over():
#     """
#     OP_2OVER, 0x70 - Copies the pair of items two spaces back in the stack to the front.
#     """
#     pass
#
# def op_2rot():
#     """
#     OP_2ROT, 0x71 - The fifth and sixth items back are moved to the top of the stack.
#     """
#     pass
#
# def op_2swap():
#     """
#     OP_2SWAP, 0x72 - Swaps the top two pairs of items.
#     """
#     pass
#
# def op_ifdup():
#     """
#     OP_IFDUP, 0x73 - If the top stack value is not 0, duplicate it.
#     """
#     pass
#
# def op_depth():
#     """
#     OP_DEPTH, 0x74 - Puts the number of stack items onto the stack.
#     """
#     pass
#
# def op_drop():
#     """
#     OP_DROP, 0x75 - Removes the top stack item.
#     """
#     pass
#
# def op_dup():
#     """
#     OP_DUP, 0x76 - Duplicates the top stack item.
#     """
#     pass
#
# def op_nip():
#     """
#     OP_NIP, 0x77 - Removes the second-to-top stack item.
#     """
#     pass
#
# def op_over():
#     """
#     OP_OVER, 0x78 - Copies the second-to-top stack item to the top.
#     """
#     pass
#
# def op_pick():
#     """
#     OP_PICK, 0x79 - The item n back in the stack is copied to the top.
#     """
#     pass
#
# def op_roll():
#     """
#     OP_ROLL, 0x7a - The item n back in the stack is moved to the top.
#     """
#     pass
#
# def op_rot():
#     """
#     OP_ROT, 0x7b - The top three items on the stack are rotated to the left.
#     """
#     pass
#
# def op_swap():
#     """
#     OP_SWAP, 0x7c - The top two items on the stack are swapped.
#     """
#     pass
#
# def op_tuck():
#     """
#     OP_TUCK, 0x7d - The item at the top of the stack is copied and inserted before the second-to-top item.
#     """
#     pass
#
# def op_size():
#     """
#     OP_SIZE, 0x82 - Pushes the string length of the top element of the stack (without popping it).
#     """
#     pass
#
# def op_equal():
#     """
#     OP_EQUAL, 0x87 - Returns 1 if the inputs are exactly equal, 0 otherwise.
#     """
#     pass
#
# def op_equalverify():
#     """
#     OP_EQUALVERIFY, 0x88 - Same as OP_EQUAL, but runs OP_VERIFY afterward.
#     """
#     pass
#
# def op_1add():
#     """
#     OP_1ADD, 0x8b - 1 is added to the input.
#     """
#     pass
#
# def op_1sub():
#     """
#     OP_1SUB, 0x8c - 1 is subtracted from the input.
#     """
#     pass
#
# def op_negate():
#     """
#     OP_NEGATE, 0x8f - The sign of the input is flipped.
#     """
#     pass
#
# def op_abs():
#     """
#     OP_ABS, 0x90 - The input is made positive.
#     """
#     pass
#
# def op_not():
#     """
#     OP_NOT, 0x91 - If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
#     """
#     pass
#
# def op_0notequal():
#     """
#     OP_0NOTEQUAL, 0x92 - Returns 0 if the input is 0. 1 otherwise.
#     """
#     pass
#
# def op_add():
#     """
#     OP_ADD, 0x93 - a is added to b.
#     """
#     pass
#
# def op_sub():
#     """
#     OP_SUB, 0x94 - b is subtracted from a.
#     """
#     pass
#
# def op_mul():
#     """
#     OP_MUL, 0x95 - a is multiplied by b.
#     """
#     pass
#
# def op_div():
#     """
#     OP_DIV, 0x96 - a is divided by b.
#     """
#     pass
#
# def op_mod():
#     """
#     OP_MOD, 0x97 - Returns the remainder after dividing a by b.
#     """
#     pass
#
# def op_lshift():
#     """
#     OP_LSHIFT, 0x98 - Shifts a left b bits, preserving sign.
#     """
#     pass
#
# def op_rshift():
#     """
#     OP_RSHIFT, 0x99 - Shifts a right b bits, preserving sign.
#     """
#     pass
#
# def op_booland():
#     """
#     OP_BOOLAND, 0x9a - If both a and b are not 0, the output is 1. Otherwise 0.
#     """
#     pass
#
# def op_boolor():
#     """
#     OP_BOOLOR, 0x9b - If a or b is not 0, the output is 1. Otherwise 0.
#     """
#     pass
#
# def op_numequal():
#     """
#     OP_NUMEQUAL, 0x9c - Returns 1 if the numbers are equal, 0 otherwise.
#     """
#     pass
#
# def op_numequalverify():
#     """
#     OP_NUMEQUALVERIFY, 0x9d - Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
#     """
#     pass
#
# def op_numnotequal():
#     """
#     OP_NUMNOTEQUAL, 0x9e - Returns 1 if the numbers are not equal, 0 otherwise.
#     """
#     pass
#
# def op_lessthan():
#     """
#     OP_LESSTHAN, 0x9f - Returns 1 if a is less than b, 0 otherwise.
#     """
#     pass
#
# def op_greaterthan():
#     """
#     OP_GREATERTHAN, 0xa0 - Returns 1 if a is greater than b, 0 otherwise.
#     """
#     pass
#
# def op_lessthanorequal():
#     """
#     OP_LESSTHANOREQUAL, 0xa1 - Returns 1 if a is less than or equal to b, 0 otherwise.
#     """
#     pass
#
# def op_greaterthanorequal():
#     """
#     OP_GREATERTHANOREQUAL, 0xa2 - Returns 1 if a is greater than or equal to b, 0 otherwise.
#     """
#     pass
#
# def op_min():
#     """
#     OP_MIN, 0xa3 - Returns the smaller of a and b.
#     """
#     pass
#
# def op_max():
#     """
#     OP_MAX, 0xa4 - Returns the larger of a and b.
#     """
#     pass
#
# def op_within():
#     """
#     OP_WITHIN, 0xa5 - Returns 1 if x is within the specified range (left-inclusive), 0 otherwise.
#     """
#     pass
#
# def op_ripemd160():
#     """
#     OP_RIPEMD160, 0xa6 - The input is hashed using RIPEMD-160.
#     """
#     pass
#
# def op_sha1():
#     """
#     OP_SHA1, 0xa7 - The input is hashed using SHA-1.
#     """
#     pass
#
# def op_sha256():
#     """
#     OP_SHA256, 0xa8 - The input is hashed using SHA-256.
#     """
#     pass
#
# def op_hash160():
#     """
#     OP_HASH160, 0xa9 - The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
#     """
#     pass
#
# def op_hash256():
#     """
#     OP_HASH256, 0xaa - The input is hashed two times with SHA-256.
#     """
#     pass
#
# def op_codeseparator():
#     """
#     OP_CODESEPARATOR, 0xab - All of the signature checking words will only match signatures to the data after the
#     most recently-executed OP_CODESEPARATOR.
#     """
#     pass
#
# def op_checksig():
#     """
#     OP_CHECKSIG, 0xac - The entire transaction's outputs, inputs, and script (from the most recently-executed
#     OP_CODESEPARATOR to the end) are hashed. The signature used by OP_CHECKSIG must be a valid signature for this
#     hash and public key.
#     """
#     pass
#
# def op_checksigverify():
#     """
#     OP_CHECKSIGVERIFY, 0xad - Same as OP_CHECKSIG, but OP_VERIFY is executed afterward.
#     """
#     pass
#
# def op_checkmultisig():
#     """
#     OP_CHECKMULTISIG, 0xae - Compares the first signature against each public key until it finds an ECDSA match.
#     Starting with the subsequent public key, it compares the second signature against each remaining public key
#     until it finds an ECDSA match. The process is repeated until all signatures have been checked or not enough
#     public keys remain to produce a successful result.
#     """
#     pass
#
# def op_checkmultisigverify():
#     """
#     OP_CHECKMULTISIGVERIFY, 0xaf - Same as OP_CHECKMULTISIG, but OP_VERIFY is executed afterward.
#     """
#     pass
#
# def op_nop1():
#     """
#     OP_NOP1, 0xb0 - Does nothing.
#     """
#     pass
#
# def op_checklocktimeverify():
#     """
#     OP_CHECKLOCKTIMEVERIFY, 0xb1 - Marks transaction as invalid if the top stack item is greater than the
#     transaction's nLockTime field.
#     """
#     pass
#
# def op_checksequenceverify():
#     """
#     OP_CHECKSEQUENCEVERIFY, 0xb2 - Marks transaction as invalid if the relative lock time of the input (enforced by
#     BIP 68 with nSequence) is not equal to or longer than the value of the top stack item.
#     """
#     pass
#
# def op_nop4():
#     """
#     OP_NOP4, 0xb3 - Does nothing.
#     """
#     pass
#
# def op_nop5():
#     """
#     OP_NOP5, 0xb4 - Does nothing.
#     """
#     pass
#
# def op_nop6():
#     """
#     OP_NOP6, 0xb5 - Does nothing.
#     """
#     pass
#
# def op_nop7():
#     """
#     OP_NOP7, 0xb6 - Does nothing.
#     """
#     pass
#
# def op_nop8():
#     """
#     OP_NOP8, 0xb7 - Does nothing.
#     """
#     pass
#
# def op_nop9():
#     """
#     OP_NOP9, 0xb8 - Does nothing.
#     """
#     pass
#
# def op_nop10():
#     """
#     OP_NOP10, 0xb9 - Does nothing.
#     """
#     pass
#
# def op_invalidopcode():
#     """
#     OP_INVALIDOPCODE, 0xff - Represents an invalid opcode.
#     """
#     pass


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
            0x93: None,  # self._op_add,  # OP_ADD
            0x94: None,  # self._op_sub,  # OP_SUB
            0x95: None,  # self._op_mul,  # OP_MUL
            0x96: None,  # self._op_div,  # OP_DIV
            0x97: None,  # self._op_mod,  # OP_MOD
            0x9a: None,  # self._op_booland,  # OP_BOOLAND
            0x9b: None,  # self._op_boolor,  # OP_BOOLOR
            0x9c: None,  # self._op_numeq,  # OP_NUMEQUAL
            0x9d: None,  # self._op_numeq_verify,  # OP_NUMEQUALVERIFY
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
    test_script_hex = "5152537b"
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
