"""
The ScriptEngine class
"""
from dataclasses import dataclass
from io import BytesIO
from typing import Callable, Dict
from typing import Optional

from src.crypto import secp256k1, ripemd160, sha1, sha256, hash160, hash256
from src.data import check_hex, check_length, encode_base58check
from src.logger import get_logger
from src.script.op_codes import OPCODES
from src.script.stack import BTCNum, BTCStack

logger = get_logger(__name__)


@dataclass
class ScriptPubKeyResult:
    scriptpubkey: bytes
    address: Optional[str]
    script_type: str


class ScriptEngine:
    """
    A class for evaluating script.

    NOTE: All elements pushed to the stack should be bytes objects.
    """

    def __init__(self, taproot: bool = False):
        """
        Setup stack and operation handlers
        """
        self.op_codes = OPCODES
        self.curve = secp256k1()
        self.stack = BTCStack()
        self.altstack = BTCStack()
        self.ops_log = []  # List of ASM instructions when evaluating script

        self.op_handlers = self._initialize_op_handlers()

        # Flag for TapScript engine
        self.taproot = taproot

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

            # crypto
            0xa6: self._op_ripemd160,  # OP_RIPEMD160
            0xa7: self._op_sha1,  # OP_SHA1
            0xa8: self._op_sha256,  # OP_SHA256
            0xa9: self._op_hash160,  # OP_HASH160
            0xaa: self._op_hash256,  # OP_HASH256
            0xac: self._op_checksig,  # OP_CHECKSIG,
            0xad: self._op_checksigverify,  # OP_CHECKSIGVERIFY
        }

    def clear_stacks(self):
        """
        Will remove all elements from main and alt stack, plus the OP log.
        """
        self.stack.clear()
        self.altstack.clear()
        self.ops_log = []

    def is_execution_enabled(self, if_stack: list):
        return all(executed for (_, executed) in if_stack)

    def eval_script(self, script: bytes, clear_stacks: bool = True) -> bool:
        """
        Evaluates the script - returns True/False based on results of main stack.
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

        # Handle execution_enabled

        # Main loop
        while valid_script:
            opcode = stream.read(1)
            if not opcode:
                # End of script - check if all IFs are properly closed
                if if_stack:
                    raise ValueError("Unbalanced IF/ENDIF in script")
                break

            opcode_int = int.from_bytes(opcode, "little")

            # Handle flow control opcodes
            if opcode_int in (0x63, 0x64, 0x67, 0x68):  # OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF
                handler = self.op_handlers.get(opcode_int)
                if handler:
                    # Pass in current execution status for conditional evaluation
                    handler(if_stack, execution_enabled)
                    execution_enabled = self.is_execution_enabled(if_stack)
                continue

            # Skip non-control opcodes if execution is currently disabled
            if not execution_enabled:
                continue

            # Check for OP_PUSHBYTES_N
            if 0x00 < opcode_int < 0x4c:
                self._push_data(stream, opcode_int)
            # Check for OP_PUSHDATA_N
            elif 0x4c <= opcode_int <= 0x4e:
                match opcode_int:
                    case 0x4c:
                        self._op_log("OP_PUSHDATA1")
                        self._push_data_n(stream, 1)  # Reads 1 byte for length encoding
                    case 0x4d:
                        self._op_log("OP_PUSHDATA2")
                        self._push_data_n(stream, 2)  # Reads 2 bytes for length encoding
                    case 0x4e:
                        self._op_log("OP_PUSHDATA4")
                        self._push_data_n(stream, 4)  # Reads 4 bytes for length encoding
            # Check for PushNum
            elif 0x50 < opcode_int < 0x61:
                num = opcode_int - 0x50
                self._op_log(f"OP_{num}")
                self.stack.push(BTCNum(num).bytes)  # Push int from 1 to 16
            else:
                self._op_log(OPCODES[opcode_int])  # Append corresponding ASM OP_CODE
                handler = self.op_handlers.get(opcode_int)
                if handler:
                    # Special handling for OP_VERIFY and OP_RETURN
                    if opcode_int == 0x69:  # OP_VERIFY
                        if not handler():
                            self._op_log("Failed OP_VERIFY")
                            valid_script = False
                    elif opcode_int == 0x6a:  # OP_RETURN
                        self._op_log("Processing OP_RETURN")
                        handler()
                        valid_script = False
                    else:
                        # Check for False returns
                        exit_val = handler()
                        if exit_val is not None and not exit_val:  # Exit val exists and is False
                            logger.debug(f"Handler {handler.__name__} returned exit val {exit_val}")
                            valid_script = False
                else:
                    logger.debug(f"Unrecognized or invalid OP code: {opcode_int:02x}")
                    valid_script = False

        # Validate stack
        return self._validate_stack() if valid_script else False

    def eval_script_from_hex(self, hex_script: str):
        clean_hex_script = check_hex(hex_script)
        bytes_eval = self.eval_script(bytes.fromhex(clean_hex_script))
        return bytes_eval

    def parse_script_from_hex(self, hex_script: str):
        clean_hex_script = check_hex(hex_script)
        parsed_script = self.parse_script(bytes.fromhex(clean_hex_script))
        return parsed_script

    def parse_script(self, script: bytes):
        """
        Outputs the corresponding ASM of the script
        """
        # Get script as byte strem
        if not isinstance(script, (bytes, BytesIO)):
            raise ValueError(f"Expected byte data stream, received {type(script)}")
        stream = BytesIO(script) if isinstance(script, bytes) else script

        asm_log = []

        while True:
            opcode = stream.read(1)
            if not opcode:
                break

            # get op_code as int value
            opcode_int = int.from_bytes(opcode, "little")

            # Determine asm
            if 0x00 < opcode_int < 0x4c:
                asm_log.append(f"OP_PUSHBYTES_{opcode_int}")
                data = stream.read(opcode_int)
                asm_log.append(data.hex())
            else:
                asm_log.append(OPCODES[opcode_int])
        return asm_log

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
            self._op_log("script failed validation: Empty stack")
            return False
        elif self.stack.height == 1:
            # Check zero element
            if self.stack.top == b'':
                self._op_log("script failed validation: Zero value")
                return False
            self._op_log("script passes validation")
            return True
        else:
            self._op_log("script failed validation: Stack height > 1")
            return False

    # --- OP_CODE FUNCTIONS --- #

    def _op_true(self):
        """OP_TRUE or OP_1 | 0x51 - Push 1 to the stack """
        self.stack.push(BTCNum(1).bytes)

    def _op_false(self):
        """OP_0 or OP_FALSE | 0x00 - Push empty bytes onto the stack"""
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
        self._op_log(f"OP_PUSHBYTES_{byte_length}")
        self._op_log(data.hex())

    def _op_1negate(self):
        """OP_1NEGATE | 0x4f - Push -1 onto the stack"""
        self.stack.push(BTCNum(-1).bytes)

    def _op_nop(self):
        """OP_NOP | 0x61 - Does nothing"""
        pass

    def _op_if(self, if_stack, execution_enabled):
        """
        OP_IF implementation
        Marks an if block. The block will be executed if the top stack value is not False.
        """
        if execution_enabled:
            condition = self.stack.pop()
            result = condition != b''
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
            result = condition != b''
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
        return False if top == b'' else True

    def _op_return(self):
        """OP_RETURN - Marks transaction as invalid"""
        return False

    def _op_to_altstack(self):
        self.altstack.push(self.stack.pop())

    def _op_from_altstack(self):
        self.stack.push(self.altstack.pop())

    def _op_ifdup(self):
        """OP_IFDUP 0x73 - Duplicates the top item on the stick iff it's non-zero"""
        if self.stack.top != b'':
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
        pick_index = BTCNum.from_bytes(self.stack.pop()).value

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
        self.stack.swap()

    def _op_tuck(self):
        self.stack.tuck()

    def _op_2drop(self):
        self.stack.pop()
        self.stack.pop()

    def _op_2dup(self):
        items = self.stack.pop_n(2)
        items = items + items
        self.stack.pushitems(list(reversed(items)))

    def _op_3dup(self):
        items = self.stack.pop_n(3)
        items = items + items
        self.stack.pushitems(list(reversed(items)))

    def _op_2over(self):
        """OP_2OVER | 0x70 - Duplicate the 3rd and 4th items in the stack"""
        items = self.stack.pop_n(4)
        items = items[2:] + items
        self.stack.pushitems(list(reversed(items)))

    def _op_2rot(self):
        """OP_2ROT | 0x71 - Move the 5th and 6th items to the top"""
        items = self.stack.pop_n(6)  # items = [top, 1, 2, 3, 4, 5]
        items = items[4:] + items[:4]  # items = [5, 6, top, 1, 2, 3]
        self.stack.pushitems(list(reversed(items)))

    def _op_2swap(self):
        """OP_2SWAP | 0x72 - Swap the top two pairs of items"""
        items = self.stack.pop_n(4)  # items = [top, 1, 2, 3]
        items = items[2:] + items[:2]  # items = [2, 3, top, 1]
        self.stack.pushitems(list(reversed(items)))

    def _op_size(self):
        # Check for empty stack
        top_element = self.stack.top if self.stack.height > 0 else b''
        self.stack.push(b'') if top_element == b'' else self.stack.push(BTCNum(len(top_element)).bytes)

    def _op_equal(self):
        items = self.stack.pop_n(2)
        self._op_true() if items[0] == items[1] else self._op_false()

    def _op_equal_verify(self):
        self._op_equal()
        return self._op_verify()

    def _op_1add(self):
        """
        OP_1ADD, 0x8b - 1 is added to the input.
        """
        self.stack.push((self._pop_num() + 1).bytes)

    def _op_1sub(self):
        """
        OP_1SUB, 0x8c - 1 is subtracted from the input.
        """
        self.stack.push((self._pop_num() - 1).bytes)

    def _op_negate(self):
        """
        OP_NEGATE, 0x8f - The sign of the input is flipped.
        """
        self.stack.push((-self._pop_num()).bytes)

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
        item = self.stack.pop()
        self._op_false() if item == b'' else self._op_true()

    def _op_add(self):
        """
        OP_ADD, 0x93 - a is added to b.
        """
        a, b = self._pop_nums(2)
        self.stack.push((a + b).bytes)

    def _op_sub(self):
        """
        OP_SUB, 0x94 - b is subtracted from a.
        """
        a, b = self._pop_nums(2)
        self.stack.push((b - a).bytes)

    def _op_booland(self):
        """
        OP_BOOLAND, 0x9a - If both a and b are not 0, the output is 1. Otherwise 0.
        """
        a, b = self.stack.pop_n(2)
        self._op_true() if a != b'' and b != b'' else self._op_false()

    def _op_boolor(self):
        """
        OP_BOOLOR, 0x9b - If a or b is not 0, the output is 1. Otherwise 0.
        """
        a, b = self.stack.pop_n(2)
        self._op_true() if a != b'' or b != b'' else self._op_false()

    def _op_numeq(self):
        """
        OP_NUMEQUAL, 0x9c - Returns 1 if the numbers are equal, 0 otherwise.
        """
        a, b = self._pop_nums(2)
        self._op_true() if a == b else self._op_false()

    def _op_numeq_verify(self):
        """
        OP_NUMEQUALVERIFY, 0x9d - Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
        """
        self._op_numeq()
        return self._op_verify()

    def _op_numneq(self):
        """
        OP_NUMNOTEQUAL, 0x9e - Returns 1 if the numbers are not equal, 0 otherwise.
        """
        a, b = self._pop_nums(2)
        self._op_true() if a != b else self._op_false()

    def _op_lt(self):
        """
        OP_LESSTHAN, 0x9f - Returns 1 if a is less than b, 0 otherwise.
        """
        a, b = self._pop_nums(2)
        self._op_true() if a < b else self._op_false()

    def _op_gt(self):
        """
        OP_GREATERTHAN, 0xa0 - Returns 1 if a is greater than b, 0 otherwise.
        """
        a, b = self._pop_nums(2)
        self._op_true() if a > b else self._op_false()

    def _op_leq(self):
        """
        OP_LESSTHANOREQUAL, 0xa1 - Returns 1 if a is less than or equal to b, 0 otherwise.
        """
        a, b = self._pop_nums(2)
        self._op_true() if a <= b else self._op_false()

    def _op_geq(self):
        """
        OP_GREATERTHANOREQUAL, 0xa2 - Returns 1 if a is greater than or equal to b, 0 otherwise.
        """
        a, b = self._pop_nums(2)
        self._op_true() if a >= b else self._op_false()

    def _op_min(self):
        """
        OP_MIN, 0xa3 - Returns the smaller of a and b.
        """
        a, b = self._pop_nums(2)
        self.stack.push(min(a, b).bytes)

    def _op_max(self):
        """
        OP_MAX, 0xa4 - Returns the larger of a and b.
        """
        a, b = self._pop_nums(2)
        self.stack.push(max(a, b).bytes)

    def _op_within(self):
        """
        OP_WITHIN, 0xa5 - Returns 1 if x is within the specified range (left-inclusive), 0 otherwise.
        """
        _max, _min, num = self._pop_nums(3)
        self._op_true() if _min <= num < _max else self._op_false()

    def _op_ripemd160(self):
        """
        OP_RIPEMD160, 0xa6 - The input is hashed using RIPEMD-160.
        """
        hashed_item = ripemd160(self.stack.pop())
        self.stack.push(hashed_item)

    def _op_sha1(self):
        """
        OP_SHA1, 0xa7 - The input is hashed using SHA-1.
        """
        hashed_item = sha1(self.stack.pop())
        self.stack.push(hashed_item)

    def _op_sha256(self):
        """
        OP_SHA256, 0xa8 - The input is hashed using SHA-256.
        """
        item = self.stack.pop()
        hashed_item = sha256(item)
        self.stack.push(hashed_item)

    def _op_hash160(self):
        """
        OP_HASH160, 0xa9 - The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
        """
        hashed_item = hash160(self.stack.pop())
        self.stack.push(hashed_item)

    def _op_hash256(self):
        """
        OP_HASH256, 0xaa - The input is hashed two times with SHA-256.
        """
        hashed_item = hash256(self.stack.pop())
        self.stack.push(hashed_item)

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

        NOTE: If taproot = true we use Schnorr signatures instead of ECDSA
        """
        pass

    def _op_checksigverify(self):
        """
        OP_CHECKSIGVERIFY, 0xad - Same as OP_CHECKSIG, but OP_VERIFY is executed afterward.
        NOTE: If taproot = true we use Schnorr signatures instead of ECDSA
        """
        pass

    def _op_checkmultisig(self):
        """
        OP_CHECKMULTISIG, 0xae - Compares the first signature against each public key until it finds an ECDSA match.
        Starting with the subsequent public key, it compares the second signature against each remaining public key
        until it finds an ECDSA match. The process is repeated until all signatures have been checked or not enough
        public keys remain to produce a successful result.

        NOTE: It Taproot = True, this OP_CODE is disabled
        """
        pass

    def _op_checkmultisigverify(self):
        """
        OP_CHECKMULTISIGVERIFY, 0xaf - Same as OP_CHECKMULTISIG, but OP_VERIFY is executed afterward.

        NOTE: It Taproot = True, this OP_CODE is disabled
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

    def _op_checksigadd(self):
        """
        OP_CHECKSIGADD, 0xba - Used in Taproot. Replaces OP_CHECKMULTISIG and OP_CHECKMULTISIGVERIFY
        """

    def _op_invalidopcode(self):
        """
        OP_INVALIDOPCODE, 0xff - Represents an invalid opcode.
        """
        pass

    # --- HELPERS --- #

    def _op_log(self, log_string: str):
        self.ops_log.append(log_string)

    def _push_data_n(self, stream: BytesIO, length_bytes: int):
        """
        Generalized function to handle Bitcoin OP_PUSHDATA1, OP_PUSHDATA2, and OP_PUSHDATA4.
        Reads `length_bytes` from the stream to determine the number of bytes to push onto the stack.
        """
        stacklen = stream.read(length_bytes)
        byte_len = BTCNum.from_bytes(stacklen).value
        self._push_data(stream, byte_len)

    def _pop_num(self):
        """
        Pops the top of the stacka and returns a BTCNum object
        """
        return BTCNum.from_bytes(self.stack.pop())

    def _pop_nums(self, count: int):
        """
        Pops 'count' items from the stack and returns their BTCNum representations
        as comma-separated values.
        """
        items = self.stack.pop_n(count)
        nums = [BTCNum.from_bytes(item) for item in items]
        return tuple(nums)


class ScriptPubKeyEngine:
    """
    A class used to create known ScriptPubKeys from a given private or public key
    """

    def __init__(self):
        self.curve = secp256k1()

    def p2pk(self, pubkey: bytes, testnet: bool = False) -> ScriptPubKeyResult:
        """
        Pay to public key
        (The address is the corresponding P2PKH address).
        """
        # Check public key type
        if len(pubkey) == 33:
            compressed = True
            print(f"COMPRESSED")
        elif len(pubkey) == 65:
            compressed = False
            print(f"NOT COMPRESSED")
        else:
            raise ValueError("Given pubkey is not of correct length")

        # OP_CODES
        op_pushbytes = b'\x21' if compressed else b'\x41'
        op_checksig = b'\xac'

        # ADDRESS | We use P2PKH address format
        prefix = b'\x00' if not testnet else b'\x6f'
        address = self.get_base58_address(hash160(pubkey), prefix)

        # ScriptPubKeyResult
        script = op_pushbytes + pubkey + op_checksig
        return ScriptPubKeyResult(scriptpubkey=script, address=address, script_type='p2pk')

    def p2pkh(self, pubkey: bytes, testnet: bool = False) -> ScriptPubKeyResult:
        """
        Pay to Public Key Hash
        """
        pubkeyhash = hash160(pubkey)

        # OPCODES
        op_dup = b'\x76'
        op_hash160 = b'\xa9'
        op_pushbytes = b'\x14'
        op_equalverify = b'\x88'
        op_checksig = b'\ac'

        # script
        script = op_dup + op_hash160 + op_pushbytes + pubkeyhash + op_equalverify + op_checksig
        prefix = b'\x00' if not testnet else b'\x6f'
        address = self.get_base58_address(pubkeyhash, prefix)

        return ScriptPubKeyResult(scriptpubkey=script, address=address, script_type="p2pkh")

    def p2ms(self, key_list: list, signum: int = None) -> ScriptPubKeyResult:
        """
        Pay To MultiSig

        Uses multiple keys to lock bitcoins, and requires some (or all) of the signatures to unlock it.
        P2MS has no address format
        """
        # signum
        numkeys = len(key_list)
        signum = numkeys if signum is None else signum

        # OPCODES
        op_reqsig = (0x50 + signum).to_bytes(1, "little")  # Required number of signatures
        op_totalsig = (0x50 + numkeys).to_bytes(1, "little")  # Total number of signatures
        op_checkmultisig = b'\xae'
        pushbytes_list = []
        for k in key_list:
            # Compressed key
            if len(k) == 33:
                pushbytes_list.append(b'\x21')
            elif len(k) == 65:
                pushbytes_list.append(b'\x41')
            else:
                raise ValueError("Key in key_list not of correct size")

        # Script
        script = op_reqsig
        for x in range(numkeys):
            script += pushbytes_list[x] + key_list[x]
        script += op_totalsig + op_checkmultisig

        return ScriptPubKeyResult(scriptpubkey=script, address=None, script_type="p2ms")

    def p2sh(self, script: bytes, testnet: bool = False) -> ScriptPubKeyResult:
        """
        Pay to Script Hash
        Given the provided script, we hash160 it and return the corresponding scriptpubkey
        """
        # Hash160
        hashed_script = hash160(script)
        print(f"HASHED SCRIPT: {hashed_script.hex()}")

        # Op Codes
        op_hash160 = b'\xa9'
        op_equal = b'\x87'
        op_pushbytes = b'\x14'

        # Script
        script = op_hash160 + op_pushbytes + hashed_script + op_equal

        # Address
        prefix = b'\x05' if not testnet else b'\xc4'
        address = self.get_base58_address(hashed_script, prefix)  # Address is the hashed script

        return ScriptPubKeyResult(scriptpubkey=script, address=address, script_type="p2sh")

    def get_base58_address(self, scriptpubkey: bytes, prefix: bytes):
        return encode_base58check(prefix + scriptpubkey)


# --- TESTING

if __name__ == "__main__":
    # test_script_hex = "528b"
    # # test_script_bytes = bytes.fromhex(test_script_hex)
    engine = ScriptEngine()
    # engine.eval_script_from_hex(test_script_hex)
    #
    # # print(f"ENGINE STACK: {engine.stack.top.hex()}")
    # print(f"STACK HEIGHT: {engine.stack.height}")
    # print(f"OP LOG: {engine.ops_log}")
    # print(f"PARSED SCRIPT: {engine.parse_script_from_hex(test_script_hex)}")
    # print(f"---- MAIN STACK PRINTOUT ----")
    # for s in range(engine.stack.height):
    #     temp_val = engine.stack.pop()
    #     print(f"STACK LEVEL: {s} || STACK ITEM: {temp_val.hex()}")
    # print("--" * 20)
    # print(f"---- ALT STACK PRINTOUT ----")
    # for s in range(engine.stack.height):
    #     temp_val = engine.stack.pop()
    #     print(f"STACK LEVEL: {s} || STACK ITEM: {temp_val.hex()}")
    # print("==" * 20)
    # print(f"SHA1 empty HEX: {sha1(b'').hex()}")
    # print(f"SHA256 empty HEX: {sha256(b'').hex()}")
    # print(f"HASH160 empty HEX: {hash160(b'').hex()} ")
    # print(f"HASH256 empty HEX: {hash256(b'').hex()}")
    # _pubkey1 = bytes.fromhex(
    #     "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")
    pubkey_engine = ScriptPubKeyEngine()
    # p2pk1 = pubkey_engine.p2pk(_pubkey1)
    # print(f"P2PK: {p2pk1.scriptpubkey.hex()}")
    # print(f"P2PK ADDRESS: {p2pk1.address}")
    # _pubkey2 = bytes.fromhex(
    #     "02bbb9c9e8b346271d5f179f4f06c83bc15e753f0800b933fabbebbede6199a3d3")
    # _pubkeyhash = hash160(_pubkey2)
    # print(f"PUBKEYHASH: {_pubkeyhash.hex()}")
    # p2pkh1 = pubkey_engine.p2pkh(_pubkey2, testnet=True)
    # print(f"ADDRESS: {p2pkh1.address}")
    #
    # pk1 = bytes.fromhex(
    #     "04d81fd577272bbe73308c93009eec5dc9fc319fc1ee2e7066e17220a5d47a18314578be2faea34b9f1f8ca078f8621acd4bc22897b03daa422b9bf56646b342a2")
    # pk2 = bytes.fromhex(
    #     "04ec3afff0b2b66e8152e9018fe3be3fc92b30bf886b3487a525997d00fd9da2d012dce5d5275854adc3106572a5d1e12d4211b228429f5a7b2f7ba92eb0475bb1")
    # pk3 = bytes.fromhex(
    #     "04b49b496684b02855bc32f5daefa2e2e406db4418f3b86bca5195600951c7d918cdbe5e6d3736ec2abf2dd7610995c3086976b2c0c7b4e459d10b34a316d5a5e7")
    #
    # p2ms1 = pubkey_engine.p2ms(key_list=[pk1, pk2, pk3], signum=2)
    # print(f"P2MS1: {p2ms1.scriptpubkey.hex()}")

    # script1 = bytes.fromhex("6e879169a77ca787")
    # p2sh1 = pubkey_engine.p2sh(script1, True)
    # print(f"P2SH SCRIPTPUBKEY: {p2sh1.scriptpubkey.hex()}")
    # print(f"P2SH ADDRESS: {p2sh1.address}")
    # parsed_script1 = engine.parse_script(script1)
    # print(f"SCRIPT1: {parsed_script1}")

    # return_script = bytes.fromhex("516351676a68")
    # return_script_parse = engine.parse_script(return_script)
    # print(f"OP_RETURN SCRIPT: {return_script_parse}")
    # result = engine.eval_script(return_script)
    # print(f"SCRIPT RESULT: {result}")

    return_script2 = bytes.fromhex("006351636a686851")
    return_script2_parse = engine.parse_script(return_script2)
    print(f"OP RETURN SCRIPT 2: {return_script2_parse}")
    result2 = engine.eval_script(return_script2)
    print(f"SCRIPT2 RESULT: {result2}")
