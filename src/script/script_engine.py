"""
Engines for Script Execution

    -Engine parent class
    -ScriptParser
    -ScriptEngine
    -ScriptPubKeyEngine
    -ScriptBuilder
"""
import operator
from io import BytesIO
from typing import Callable, Dict, Optional

from src.crypto import ripemd160, sha1, sha256, hash160, hash256
from src.data import check_hex
from src.logger import get_logger
from src.script.op_codes import OPCODES
from src.script.signature_engine import SignatureEngine, SigHash
from src.script.stack import BTCStack, BTCNum
from src.tx import Transaction, UTXO

logger = get_logger(__name__)

__all__ = ["ScriptEngine"]


class ScriptEngine:
    """
    Evalute Script
    """

    def __init__(self, tapscript: bool = False):
        """
        Setup stack and operation handlers
        """
        self.op_codes = OPCODES
        self.stack = BTCStack()
        self.altstack = BTCStack()
        self.ops_log = []  # List of ASM instructions when evaluating script

        self.op_handlers = self._initialize_op_handlers()

        # Flag for TapScript engine
        self.tapscript = tapscript

        # Save context for opcode handlers
        self._tx = None
        self._input_index = None
        self._utxo = None
        self._script_code = None
        self._amount = None

        # SigEngine for OP_CHECKSIG and related functionality
        self.sig_engine = SignatureEngine()

    # -- OPCODE HANLDERS

    def _initialize_op_handlers(self) -> Dict[int, Callable]:
        return {
            # Constants
            0x00: self._op_false,  # OP_0, OP_FALSE
            0x4f: self._op_1negate,  # OP_1NEGATE
            0x51: self._op_true,  # OP_1, OP_TRUE

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

    # -- HELPERS

    def _op_log(self, log_string: str):
        self.ops_log.append(log_string)

    def clear_stacks(self):
        """
        Will remove all elements from main and alt stack, plus the OP log.
        """
        self.stack.clear()
        self.altstack.clear()
        self.ops_log = []

    def _validate_stack(self) -> bool:
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

    def _dispatch_opcode(self, opcode: int) -> bool:
        handler = self.op_handlers.get(opcode)
        if not handler:
            logger.warning(f"Unknown opcode: {opcode:02x}")
            return False
        try:
            result = handler()
            return True if result is None else result
        except Exception as e:
            logger.error(f"Error executing opcode {opcode:02x}: {e}")
            return False

    def _read_opcode(self, stream: BytesIO) -> int:
        byte = stream.read(1)
        return int.from_bytes(byte, "little") if byte else None

    def _handle_pushdata(self, stream: BytesIO, opcode: int):
        data = stream.read(opcode)
        self.stack.push(data)

    def _handle_pushdata_n(self, stream: BytesIO, length: int):
        stacklen = stream.read(length)
        opcode = BTCNum.from_bytes(stacklen).value
        self._handle_pushdata(stream, opcode)

    def _handle_checksig(self, opcode: int):
        # Verify tx, input_index and utxo passed in
        if self._tx is None or self._utxo is None:  # or self._input_index is None
            raise ValueError(f"Called {OPCODES[opcode]} without tx and/or input_index and/or utxo")

        if self.tapscript:
            if opcode == 0xba:
                self._handle_checksigadd()
            elif opcode == 0xac:
                self._handle_opchecksig()
            else:
                raise ValueError("Invalid opcode in Taproot context")
        else:
            if opcode in (0xac, 0xad):  # OP_CHECKSIG, OP_CHECKSIGVERIFY
                self._handle_opchecksig()
                if opcode == 0xad:
                    self._op_verify()
            elif opcode == 0xae:  # OP_CHECKSIGALL (multisig)
                self._handle_multisig()
            else:
                raise ValueError(f"Unexpected signature opcode: {hex(opcode)}")

    def _handle_checksigadd(self):
        pass

    def _handle_opchecksig(self):
        """
        Handles the OP_CHECKSIG for both legacy and segwit txs
        """
        # Pop pubkey and signature from stack
        pubkey, signature = self.stack.pop_n(2)

        # Verify sig
        if not self.tapscript:
            is_valid = self._verify_sig(signature, pubkey)
        else:
            is_valid = self._verify_schnorr_sig(signature, pubkey)

        # Push result
        self.stack.push_bool(is_valid)

    def _handle_tapchecksig(self):
        """
        Handles OP_CHECKSIG for Taproot signatures
        """

    def _handle_multisig(self):
        """
        Implements OP_CHECKMULTISIG logic.
        """

        # Step 1: Extract values
        sig_count = self.stack.pop_num().value  # e.g. 2
        pubkeys = self.stack.pop_n(sig_count)  # pubkey_N .. pubkey_1
        pub_count = self.stack.pop_num().value  # e.g. 3
        sigs = self.stack.pop_n(pub_count)  # sig_M .. sig_1
        empty_byte = self.stack.pop()

        if empty_byte != b'':
            raise ValueError("Missing dummy OP_0 before signatures (required due to off-by-one bug)")

        # Step 2: Initialize indexes
        sig_index = 0
        key_index = 0
        matches = 0

        # Step 3: Try to match signatures to public keys
        while sig_index < len(sigs) and key_index < len(pubkeys):
            sig = sigs[sig_index]
            pub = pubkeys[key_index]

            if self._verify_sig(sig, pub):
                matches += 1
                sig_index += 1

            key_index += 1  # always advance key_index

        # Step 4: Validation result
        if matches == len(sigs):
            self._op_true()
        else:
            self._op_false()

    def _verify_sig(self, signature: bytes, pubkey: bytes):
        """
        Verifies a signature against a pubkey using the transaction context.
        Handles both legacy and segwit sighash methods.
        """
        # Decode signature and sighash
        der_sig = signature[:-1]
        sighash_flag = signature[-1]

        # Compute message hash
        if self._tx.segwit:
            # Segwit path
            if self._amount is None:
                raise ValueError("Segwit checksig missing amount value")

            message_hash = self.sig_engine.get_segwit_sighash(
                tx=self._tx,
                input_index=self._input_index,
                script_code=self._script_code,
                amount=self._amount,
                sighash_flag=sighash_flag
            )

        else:
            # Legacy path
            message_hash = self.sig_engine.get_legacy_sighash(
                tx=self._tx,
                input_index=self._input_index,
                script_pubkey=self._utxo.script_pubkey,
                sighash_flag=sighash_flag
            )

        # Verify signature
        return self.sig_engine.verify_sig(der_sig, pubkey, message_hash)

    def _verify_schnorr_sig(self, signature: bytes, xonly_pubkey: bytes):
        """
        Verifies a signature against a pubkey using the transaction context.
        Handles both legacy and segwit sighash methods.
        """
        # Decode signature and sighash
        sig = signature[:-1]
        sighash_flag = signature[-1]

        taproot_sighash = self.sig_engine.get_taproot_sighash(
            tx=self._tx,
            input_index=self._input_index,
            utxos=[self._utxo],
            extension=self._script_code,
            hash_type=SigHash(sighash_flag)
        )

        return self.sig_engine.verify_schnorr_signature(int.from_bytes(xonly_pubkey, "big"), taproot_sighash, sig)

    # -- EVAL

    def eval_script(
            self,
            script: bytes | str,
            tx: Transaction = None,
            input_index: int = None,
            utxo: Optional[UTXO] = None,
            amount: Optional[int] = None,
            script_code: Optional[bytes] = None,
            clear_stacks: bool = True
    ) -> bool:
        """
        Evaluate a Bitcoin script and return success/failure.
        """
        # Empty stacks
        if clear_stacks:
            self.clear_stacks()

        # Save context for opcode handlers
        self._tx = tx
        self._input_index = input_index
        self._utxo = utxo
        self._amount = amount
        self._script_code = script_code

        # Byte encode script if str
        if isinstance(script, str):
            # Check hex
            try:
                hex_script = check_hex(script)
                script = bytes.fromhex(hex_script)
            except ValueError as e:
                raise ValueError(f"Error evaluating hex script: {e}")

        # Get script as byte strem
        if not isinstance(script, (bytes, BytesIO)):
            raise ValueError(f"Expected byte data stream, received {type(script)}")
        stream = BytesIO(script) if isinstance(script, bytes) else script

        # Control flow tracking
        if_stack = []
        execution_enabled = True
        valid_script = True

        flow_opcodes = {0x63, 0x64, 0x67, 0x68}  # IF, NOTIF, ELSE, ENDIF

        def is_execution_enabled():
            return all(executed for (_, executed) in if_stack)

        while valid_script:
            opcode = self._read_opcode(stream)

            # End of script
            if opcode is None:
                # Check if all IF's are properly closed
                if if_stack:
                    raise ValueError("Unbalanced IF/ENDIF in script")
                break

            # Handle flow control opcodes
            if opcode in flow_opcodes:
                handler = self.op_handlers.get(opcode)
                if handler:
                    # Pass in current execution status for conditional evaluation
                    handler(if_stack, execution_enabled)
                    execution_enabled = is_execution_enabled()
                continue

            # Skip non-control opcodes if execution is currently disabled
            if not execution_enabled:
                continue

            # 0x00 -- OP_0, OP_FALSE
            if opcode == 0x00:
                self.stack.push_bool(False)
                continue

            # 0x01 -- 0x4b - OP_PUSHBYTES
            if 0x01 <= opcode <= 0x4b:
                self._handle_pushdata(stream, opcode)
                continue

            # 0x4c, 0x4d, 0x4e - OP_PUSHDATAn

            if opcode in (0x4c, 0x4d, 0x4e):
                self._handle_pushdata_n(stream, {0x4c: 1, 0x4d: 2, 0x4e: 4}[opcode])
                continue

            # 0x51 -- 0x60 - OP_1 -- OP_16
            if 0x51 <= opcode <= 0x60:
                self.stack.push(BTCNum(opcode - 0x50).bytes)
                continue

            # 0xac -- 0xba - OP_CHECKSIGS
            if 0xac <= opcode <= 0xba:
                self._handle_checksig(opcode)
                continue

            valid_script = self._dispatch_opcode(opcode)

        return self._validate_stack() if valid_script else False

    # -- OPCODE FUNCTIONS
    def _op_false(self):
        """
        OP_0, OP_FALSE | 0x00
        Push empty byte array to stack
        """
        self.stack.op_false()

    def _op_1negate(self):
        """
        OP_1NEGATE | 0x4f
        Push -1 onto the stack
        """
        self.stack.push(BTCNum(-1).bytes)

    def _op_true(self):
        """
        OP_1, OP_TRUE | 0x51
        Push 1 to the stack
        """
        self.stack.op_true()

    def _op_nop(self):
        """
        OP_NOP | 0x61
        Does nothing
        """
        pass

    def _op_if(self, if_stack, execution_enabled):
        """
        OP_IF | 0x63
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
        OP_NOTIF | 0x64
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
        OP_ELSE | 0x67
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
        OP_ENDIF | 0x68
        Marks the end of an if/else block.
        """
        if not if_stack:
            raise ValueError("OP_ENDIF without matching OP_IF/OP_NOTIF/OP_ELSE")

        if_stack.pop()
        # Compute new execution_enabled based on remaining if_stack
        new_execution = all(executed for _, executed in if_stack)
        return new_execution

    def _op_verify(self):
        """
        OP_VERIFY | 0x69
        Verify the top element is truthy
        """
        top = self.stack.pop()
        return False if top == b'' else True

    def _op_return(self):
        """
        OP_RETURN | 0x 6a
        Marks transaction as invalid
        """
        return False

    def _op_to_altstack(self):
        """
        OP_TOALTSTACK | 0x6b
        Puts the input onto the top of the alt stack. Removes it from the main stack.
        """
        self.altstack.push(self.stack.pop())

    def _op_from_altstack(self):
        """
        OP_FROMALTSTACK | 0x6c
        Puts the input onto the top of the main stack. Removes it from the alt stack.
        """
        self.stack.push(self.altstack.pop())

    def _op_ifdup(self):
        """
        OP_IFDUP |  0x73
        Duplicates the top item on the stick iff it's non-zero
        """
        if self.stack.top != b'':
            self.stack.push(self.stack.top)

    def _op_depth(self):
        """
        OP_DEPTH | 0x74
        Puts the number of stack items onto the stack.
        """
        self.stack.push(BTCNum(self.stack.height).bytes)

    def _op_drop(self):
        """
        OP_DROP | 0x75
        Removes the top stack item.
        """
        self.stack.pop()

    def _op_dup(self):
        """
        OP_DUP | 0x76
        Duplicates the top stack item.
        """
        self.stack.push(self.stack.top)

    def _op_nip(self):
        """
        OP_NIP | -x77
        Removes the second-to-top stack item
        """
        self.stack.nip()

    def _op_over(self):
        """
        OP_OVER | 0x78
        Copies the second-to-top stack item to the top.
        """
        self.stack.over()

    def _op_pick(self):
        """
        OP_PICK | 0x79
        The item n back in the stack is copied to the top.
        """
        n = self.stack.pop_num()  # n is BTCNum object

        # Check height
        if self.stack.height <= n.value:
            raise ValueError("Incorrect pick index")

        pick_item = self.stack.stack[n.value]  # Indexed at 0
        self.stack.push(pick_item)

    def _op_roll(self):
        """
        OP_ROLL | 0x7a
        The item n back in the stack is moved to the top.
        """
        n = self.stack.pop_num()  # n is BTCNum object
        self.stack.roll(n.value)

    def _op_rot(self):
        """
        OP_ROT | 0x7b
        The 3rd item down the stack is moved to the top.
        """
        self.stack.rot()

    def _op_swap(self):
        """
        OP_SWAP | 0x7c
        The top two items on the stack are swapped.
        """
        self.stack.swap()

    def _op_tuck(self):
        """
        OP_TUCK | 0x7d
        The item at the top of the stack is copied and inserted before the second-to-top item.
        """
        self.stack.tuck()

    def _op_2drop(self):
        """
        OP_2DROP | 0x6d
        Removes the top two stack items.
        """
        self.stack.pop()
        self.stack.pop()

    def _op_2dup(self):
        """
        OP_2DUP | 0x6e
        Duplicates the top two stack items.
        """
        items = self.stack.pop_n(2)
        items = items + items
        self.stack.pushitems(list(reversed(items)))

    def _op_3dup(self):
        """
        OP_3DUP | 0x6f
        Duplicates the top three stack items.
        """
        items = self.stack.pop_n(3)
        items = items + items
        self.stack.pushitems(list(reversed(items)))

    def _op_2over(self):
        """
        OP_2OVER | 0x70
        Duplicate the 3rd and 4th items in the stack
        """
        items = self.stack.pop_n(4)
        items = items[2:] + items
        self.stack.pushitems(list(reversed(items)))

    def _op_2rot(self):
        """
        OP_2ROT | 0x71
        Move the 5th and 6th items to the top
        """
        items = self.stack.pop_n(6)  # items = [top, 1, 2, 3, 4, 5]
        items = items[4:] + items[:4]  # items = [5, 6, top, 1, 2, 3]
        self.stack.pushitems(list(reversed(items)))

    def _op_2swap(self):
        """
        OP_2SWAP | 0x72
        Swap the top two pairs of items
        """
        items = self.stack.pop_n(4)  # items = [top, 1, 2, 3]
        items = items[2:] + items[:2]  # items = [2, 3, top, 1]
        self.stack.pushitems(list(reversed(items)))

    def _op_size(self):
        """
        OP_SIZE | 0x82
        Pushes the string length of the top element of the stack (without popping it)
        """
        top_element = self.stack.top if self.stack.height > 0 else b''
        self.stack.push(b'') if top_element == b'' else self.stack.push(BTCNum(len(top_element)).bytes)

    def _op_equal(self):
        """
        OP_EQUAL | 0x87
        Returns 1 if the inputs are exactly equal, 0 otherwise.
        """
        items = self.stack.pop_n(2)
        self.stack.push_bool(items[0] == items[1])

    def _op_equal_verify(self):
        """
        OP_EQUALVERIFY | 0x88
        Same as OP_EQUAL, but runs OP_VERIFY afterward.
        """
        self._op_equal()
        return self._op_verify()

    def _op_1add(self):
        """
        OP_1ADD | 0x8b
        1 is added to the input.
        """
        self.stack.push((self.stack.pop_num() + 1).bytes)

    def _op_1sub(self):
        """
        OP_1SUB | 0x8c
        1 is subtracted from the input.
        """
        self.stack.push((self.stack.pop_num() - 1).bytes)

    def _op_negate(self):
        """
        OP_NEGATE | 0x8f
        The sign of the input is flipped.
        """
        self.stack.push((-self.stack.pop_num()).bytes)

    def _op_abs(self):
        """
        OP_ABS |  0x90
        The input is made positive.
        """
        stack_num = self.stack.pop_num()
        self.stack.push(abs(stack_num).bytes)

    def _op_not(self):
        """
        OP_NOT | 0x91
        If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
        """
        item = self.stack.pop()
        self.stack.push_bool(item == b'')

    def _op_0notequal(self):
        """
        OP_0NOTEQUAL | 0x92
        Returns 0 if the input is 0. 1 otherwise.
        """
        item = self.stack.pop()
        self.stack.push_bool(item != b'')

    def _op_add(self):
        """
        OP_ADD |  0x93
        a is added to b.
        """
        self.stack.binary_op(operator.add)

    def _op_sub(self):
        """
        OP_SUB |  0x94
        b is subtracted from a.
        """
        a, b = self.stack.pop_nums(2)
        self.stack.push((b - a).bytes)

    def _op_booland(self):
        """
        OP_BOOLAND | 0x9a
        If both a and b are not 0, the output is 1. Otherwise 0.
        """
        a, b = self.stack.pop_n(2)
        self.stack.push_bool(a != b'' and b != b'')

    def _op_boolor(self):
        """
        OP_BOOLOR |  0x9b
        If a or b is not 0, the output is 1. Otherwise 0.
        """
        a, b = self.stack.pop_n(2)
        self.stack.push_bool(a != b'' or b != b'')

    def _op_numeq(self):
        """
        OP_NUMEQUAL | 0x9c
        Returns 1 if the numbers are equal, 0 otherwise.
        """
        a, b = self.stack.pop_nums(2)
        self.stack.push_bool(a == b)

    def _op_numeq_verify(self):
        """
        OP_NUMEQUALVERIFY | 0x9d
        Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
        """
        self._op_numeq()
        return self._op_verify()

    def _op_numneq(self):
        """
        OP_NUMNOTEQUAL | 0x9e
        Returns 1 if the numbers are not equal, 0 otherwise.
        """
        a, b = self.stack.pop_nums(2)
        self.stack.push_bool(a != b)

    def _op_lt(self):
        """
        OP_LESSTHAN | 0x9f
        Returns 1 if a is less than b, 0 otherwise.
        """
        a, b = self.stack.pop_nums(2)
        self.stack.push_bool(a < b)

    def _op_gt(self):
        """
        OP_GREATERTHAN | 0xa0
        Returns 1 if a is greater than b, 0 otherwise.
        """
        a, b = self.stack.pop_nums(2)
        self.stack.push_bool(a > b)

    def _op_leq(self):
        """
        OP_LESSTHANOREQUAL | 0xa1
        Returns 1 if a is less than or equal to b, 0 otherwise.
        """
        a, b = self.stack.pop_nums(2)
        self.stack.push_bool(a <= b)

    def _op_geq(self):
        """
        OP_GREATERTHANOREQUAL | 0xa2
        Returns 1 if a is greater than or equal to b, 0 otherwise.
        """
        a, b = self.stack.pop_nums(2)
        self.stack.push_bool(a >= b)

    def _op_min(self):
        """
        OP_MIN | 0xa3
        Returns the smaller of a and b.
        """
        a, b = self.stack.pop_nums(2)
        self.stack.push(min(a, b).bytes)

    def _op_max(self):
        """
        OP_MAX | 0xa4
        Returns the larger of a and b.
        """
        a, b = self.stack.pop_nums(2)
        self.stack.push(max(a, b).bytes)

    def _op_within(self):
        """
        OP_WITHIN | 0xa5
        Returns 1 if x is within the specified range (left-inclusive), 0 otherwise.
        """
        _max, _min, num = self.stack.pop_nums(3)
        self.stack.push_bool(_min <= num < _max)

    def _op_ripemd160(self):
        """
        OP_RIPEMD160 | 0xa6
        The input is hashed using RIPEMD-160.
        """
        hashed_item = ripemd160(self.stack.pop())
        self.stack.push(hashed_item)

    def _op_sha1(self):
        """
        OP_SHA1 |  0xa7
        The input is hashed using SHA-1.
        """
        hashed_item = sha1(self.stack.pop())
        self.stack.push(hashed_item)

    def _op_sha256(self):
        """
        OP_SHA256 | 0xa8
        The input is hashed using SHA-256.
        """
        hashed_item = sha256(self.stack.pop())
        self.stack.push(hashed_item)

    def _op_hash160(self):
        """
        OP_HASH160 | 0xa9
        The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
        """
        # TODO: Handle P2SH scripts here
        hashed_item = hash160(self.stack.pop())
        self.stack.push(hashed_item)

    def _op_hash256(self):
        """
        OP_HASH256 | 0xaa
        The input is hashed two times with SHA-256.
        """
        hashed_item = hash256(self.stack.pop())
        self.stack.push(hashed_item)

    def _op_codeseparator(self):
        """
        OP_CODESEPARATOR |  0xab
        All of the signature checking words will only match signatures to the data after the most recently-executed
        OP_CODESEPARATOR.
        """
        pass

    def _op_checksig(self):
        """
        OP_CHECKSIG | 0xac
        The entire transaction's outputs, inputs, and script (from the most recently-executed OP_CODESEPARATOR to the
        end) are hashed. The signature used by OP_CHECKSIG must be a valid signature for this
        hash and public key.

        NOTE: If tapscript = true we use Schnorr signatures instead of ECDSA
        """
        pass

    def _op_checksigverify(self):
        """
        OP_CHECKSIGVERIFY | 0xad
        Same as OP_CHECKSIG, but OP_VERIFY is executed afterward.
        """
        # self._op_checksig()
        # self._op_verify()
        pass

    def _op_checkmultisig(self):
        """
        OP_CHECKMULTISIG | 0xae
        Compares the first signature against each public key until it finds an ECDSA match. Starting with the
        subsequent public key, it compares the second signature against each remaining public key until it finds an
        ECDSA match. The process is repeated until all signatures have been checked or not enough public keys remain
        to produce a successful result.

        NOTE: If tapscript = True, this OP_CODE is disabled
        """
        pass

    def _op_checkmultisigverify(self):
        """
        OP_CHECKMULTISIGVERIFY |  0xaf
        Same as OP_CHECKMULTISIG, but OP_VERIFY is executed afterward.

        NOTE: If tapscript = True, this OP_CODE is disabled
        """
        pass

    def _op_nop1(self):
        """
        OP_NOP1 |  0xb0
        Does nothing.
        """
        pass

    def _op_checklocktimeverify(self):
        """
        OP_CHECKLOCKTIMEVERIFY | 0xb1
        Marks transaction as invalid if the top stack item is greater than the transaction's nLockTime field.
        """
        pass

    def _op_checksequenceverify(self):
        """
        OP_CHECKSEQUENCEVERIFY | 0xb2
        Marks transaction as invalid if the relative lock time of the input (enforced by BIP 68 with nSequence) is
        not equal to or longer than the value of the top stack item.
        """
        pass

    def _op_nop4(self):
        """
        OP_NOP4 | 0xb3
        Does nothing.
        """
        pass

    def _op_nop5(self):
        """
        OP_NOP5 | 0xb4
        Does nothing.
        """
        pass

    def _op_nop6(self):
        """
        OP_NOP6 | 0xb5
        Does nothing.
        """
        pass

    def _op_nop7(self):
        """
        OP_NOP7 | 0xb6
        Does nothing.
        """
        pass

    def _op_nop8(self):
        """
        OP_NOP8 | 0xb7
        Does nothing.
        """
        pass

    def _op_nop9(self):
        """
        OP_NOP9 | 0xb8
        Does nothing.
        """
        pass

    def _op_nop10(self):
        """
        OP_NOP10 | 0xb9
        Does nothing.
        """
        pass

    def _op_checksigadd(self):
        """
        OP_CHECKSIGADD | 0xba
        Used in tapscript. Replaces OP_CHECKMULTISIG and OP_CHECKMULTISIGVERIFY
        """
        pass

    def _op_invalidopcode(self):
        """
        OP_INVALIDOPCODE | 0xff - Represents an invalid opcode.
        """
        return False
