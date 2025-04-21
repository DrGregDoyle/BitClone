"""
Engines for Script Execution

    -Engine parent class
    -ScriptParser
    -ScriptEngine
    -ScriptPubKeyEngine
    -ScriptSigEngine
"""
import operator
from io import BytesIO
from typing import Callable, Dict

from src.crypto import secp256k1, ripemd160, sha1, sha256, hash160, hash256, verify_ecdsa
from src.data import check_hex, decode_der_signature, write_compact_size, get_public_key_point
from src.db import BitCloneDatabase, DB_PATH
from src.logger import get_logger
from src.script.op_codes import OPCODES
from src.script.sighash import SigHash
from src.script.stack import BTCStack, OpcodeMixin, BTCNum
from src.tx import Transaction, UTXO

logger = get_logger(__name__)


class ScriptEngine(OpcodeMixin):
    """
    Evalute Script
    """

    def __init__(self, db: BitCloneDatabase = DB_PATH, taproot: bool = False):
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

        # Load DB
        self.db = db

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

    def _clear_stacks(self):
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
            print(f"Unknown opcode: {opcode:02x}")
            return False
        try:
            result = handler()
            return True if result is None else result
        except Exception as e:
            print(f"Error executing opcode {opcode:02x}: {e}")
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

    def _handle_checksig(self, opcode: int, tx: Transaction, input_index: int):
        if self.taproot:
            if opcode == 0xba:
                self._handle_checksigadd(tx, input_index)
            else:
                raise ValueError("Invalid opcode in Taproot context")
        else:
            if opcode == 0xac:  # OP_CHECKSIG
                self._handle_legacy_checksig(tx, input_index)
            elif opcode == 0xad:  # OP_CHECKSIGVERIFY
                self._handle_legacy_checksig(tx, input_index)
                self._op_verify()
                # return self._op_verify_result(result)
            elif opcode == 0xae:  # OP_CHECKSIGALL
                self._handle_multisig(tx, input_index)
            else:
                raise ValueError(f"Unexpected signature opcode: {hex(opcode)}")

    def _handle_checksigadd(self, tx: Transaction, input_index: int):
        pass

    def _handle_multisig(self, tx: Transaction = None, input_index: int = 0):
        """
        Implements OP_CHECKMULTISIG logic.
        """

        # Step 1: Extract values
        sig_count = self._pop_num().value  # e.g. 2
        pubkeys = self.stack.pop_n(sig_count)  # pubkey_N .. pubkey_1
        pub_count = self._pop_num().value  # e.g. 3
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

            if self._verify_sig(sig, pub, tx, input_index):
                matches += 1
                sig_index += 1

            key_index += 1  # always advance key_index

        # Step 4: Validation result
        if matches == len(sigs):
            self._op_true()
        else:
            self._op_false()

    def _handle_legacy_checksig(self, tx: Transaction, input_index: int):
        if tx is None or input_index is None:
            raise ValueError("Missing either tx or input_index")

        # Pop pubkey and signature, in that order
        pubkey, signature = self.stack.pop_n(2)

        # Get signature tuple
        der_sig = signature[:-1]
        hash_type = signature[-1]
        sig_tuple = decode_der_signature(der_sig)

        # copy tx
        tx_copy = Transaction.from_bytes(tx.to_bytes())

        # Get input utxo
        tx_input = tx_copy.inputs[input_index]
        utxo_tuple = self.db.get_utxo(tx_input.txid, tx_input.vout)
        utxo = UTXO(utxo_tuple[0], utxo_tuple[1], utxo_tuple[2], utxo_tuple[3], bool(utxo_tuple[4]))
        subscript = utxo.script_pubkey

        # scriptsigs for all inputs in tx_copy set to empty scripts
        for x in range(len(tx_copy.inputs)):
            temp_input = tx_copy.inputs[x]
            temp_input.script_sig = bytes()  # Empty Script
            temp_input.script_sig_size = write_compact_size(0)  # Null byte length for encoding
            tx_copy.inputs[x] = temp_input

        # Change input script sig to scriptpubkey from utxo
        tx_input.script_sig = subscript
        tx_input.script_sig_size = write_compact_size(len(subscript))

        print(f"OP_CHECKSIG TX BEFORE HASHING: {tx_copy.to_json()}")

        # Get data to hash
        sighash_type = SigHash(hash_type)
        data = tx_copy.to_bytes() + sighash_type.for_hashing()  # Returns 4 byte for hash
        message_hash = hash256(data)
        print(f"OP_CHECKSIG MESSAGE HASH: {message_hash.hex()}")

        # Get public key point
        pubkey_point = get_public_key_point(pubkey)

        # Verify point is on curve
        if not self.curve.is_point_on_curve(pubkey_point):
            raise ValueError(f"OP_CHECKSIG FAILED TO GET POINT ON CURVE")

        # Verify ECDSA
        valid_signature = verify_ecdsa(sig_tuple, message_hash, pubkey_point)
        self._push_bool(valid_signature)

    def _verify_sig(self, sig: bytes, pubkey: bytes, tx: Transaction, input_index: int) -> bool:
        try:
            sig_val = sig[:-1]  # DER part
            sighash_flag = sig[-1]
            message_hash = self._get_sighash(tx, input_index, sighash_flag)
            pub_point = get_public_key_point(pubkey)
            r, s = decode_der_signature(sig_val)
            return verify_ecdsa((r, s), message_hash, pub_point)
        except ValueError as e:
            logger.debug(f"Verify multisig failed with error: {e}")
            return False

    def _get_sighash(self, tx: Transaction, input_index: int, sighash_flag: int) -> bytes:
        """
        Constructs the sighash digest for legacy transactions (non-SegWit).

        This is the digest that is signed or verified for a given input.
        """
        # Step 1: Copy tx to avoid mutation
        tx_copy = Transaction.from_bytes(tx.to_bytes())

        # Step 2: Clear all scriptSigs
        for txin in tx_copy.inputs:
            txin.script_sig = b''
            txin.script_sig_size = write_compact_size(0)

        # Step 3: Insert scriptPubKey from UTXO at the input being signed
        utxo = self.db.get_utxo(tx_copy.inputs[input_index].txid, tx_copy.inputs[input_index].vout)
        if utxo is None:
            raise ValueError("UTXO not found during sighash computation")
        script_pubkey = utxo[3]  # script is 4th item in returned tuple
        tx_copy.inputs[input_index].script_sig = script_pubkey
        tx_copy.inputs[input_index].script_sig_size = write_compact_size(len(script_pubkey))

        # Step 4: Append 4-byte sighash flag (little-endian)
        sighash_bytes = sighash_flag.to_bytes(4, "little")
        serialized = tx_copy.to_bytes() + sighash_bytes

        # Step 5: Return double SHA256
        return hash256(serialized)

    # -- EVAL

    def eval_script(self, script: bytes | str, tx: Transaction = None, input_index: int = None, clear_stacks: bool =
    True) -> bool:
        """
        Evaluate a Bitcoin script and return success/failure.
        """
        # Empty stacks
        if clear_stacks:
            self._clear_stacks()

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
                self._push_bool(False)
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
                self._handle_checksig(opcode, tx, input_index)
                continue

            valid_script = self._dispatch_opcode(opcode)

        return self._validate_stack() if valid_script else False

    def validate_utxo(self, script_sig: bytes, script_pubkey: bytes, tx: Transaction, input_index: int = 0) -> bool:
        """
        Validates input scriptSig + scriptPubKey (and redeemScript if P2SH).
        """
        self._clear_stacks()

        # --- Step 1: Evaluate scriptSig
        self.eval_script(script_sig, tx, input_index)
        logger.debug("Stack has evaluated scriptsig")

        # --- Step 2: Check for P2SH
        is_p2sh = (
                len(script_pubkey) == 23 and
                script_pubkey[0] == 0xa9 and  # OP_HASH160
                script_pubkey[1] == 0x14 and  # PUSH 20 bytes
                script_pubkey[-1] == 0x87  # OP_EQUAL
        )

        if not is_p2sh:
            # Evaluate scriptPubKey using resulting stack from scriptSig
            return self.eval_script(script_pubkey, tx, input_index, clear_stacks=False)

        # --- Step 3: Handle P2SH
        if self.stack.height == 0:
            logger.debug("P2SH redeem script missing")
            return False

        redeem_script = self.stack.pop()
        # Push redeem_script to be hashed and compared by scriptPubKey
        self.stack.push(redeem_script)

        # Evaluate the P2SH scriptPubKey (e.g., OP_HASH160 <20B> OP_EQUAL)
        self.eval_script(script_pubkey, tx, input_index, clear_stacks=False)

        # Pop top element and verify OP_EQUAL
        op_equal = self.stack.pop()
        if not op_equal == b'\x01':
            logger.debug("P2SH ScriptPubKey failed HASH160 verification")
            return False

        # Step 4: Evaluate the redeem script using *current stack*
        return self.eval_script(redeem_script, tx, input_index, clear_stacks=False)

    # -- OPCODE FUNCTIONS
    def _op_1negate(self):
        """
        OP_1NEGATE | 0x4f
        Push -1 onto the stack
        """
        self.stack.push(BTCNum(-1).bytes)

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
        n = self._pop_num()  # n is BTCNum object

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
        n = self._pop_num()  # n is BTCNum object
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
        self._push_bool(items[0] == items[1])

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
        self.stack.push((self._pop_num() + 1).bytes)

    def _op_1sub(self):
        """
        OP_1SUB | 0x8c
        1 is subtracted from the input.
        """
        self.stack.push((self._pop_num() - 1).bytes)

    def _op_negate(self):
        """
        OP_NEGATE | 0x8f
        The sign of the input is flipped.
        """
        self.stack.push((-self._pop_num()).bytes)

    def _op_abs(self):
        """
        OP_ABS |  0x90
        The input is made positive.
        """
        stack_num = self._pop_num()
        self.stack.push(abs(stack_num).bytes)

    def _op_not(self):
        """
        OP_NOT | 0x91
        If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
        """
        item = self.stack.pop()
        self._push_bool(item == b'')

    def _op_0notequal(self):
        """
        OP_0NOTEQUAL | 0x92
        Returns 0 if the input is 0. 1 otherwise.
        """
        item = self.stack.pop()
        self._push_bool(item != b'')

    def _op_add(self):
        """
        OP_ADD |  0x93
        a is added to b.
        """
        self._binary_op(operator.add)

    def _op_sub(self):
        """
        OP_SUB |  0x94
        b is subtracted from a.
        """
        a, b = self._pop_nums(2)
        self.stack.push((b - a).bytes)

    def _op_booland(self):
        """
        OP_BOOLAND | 0x9a
        If both a and b are not 0, the output is 1. Otherwise 0.
        """
        a, b = self.stack.pop_n(2)
        self._push_bool(a != b'' and b != b'')

    def _op_boolor(self):
        """
        OP_BOOLOR |  0x9b
        If a or b is not 0, the output is 1. Otherwise 0.
        """
        a, b = self.stack.pop_n(2)
        self._push_bool(a != b'' or b != b'')

    def _op_numeq(self):
        """
        OP_NUMEQUAL | 0x9c
        Returns 1 if the numbers are equal, 0 otherwise.
        """
        a, b = self._pop_nums(2)
        self._push_bool(a == b)

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
        a, b = self._pop_nums(2)
        self._push_bool(a != b)

    def _op_lt(self):
        """
        OP_LESSTHAN | 0x9f
        Returns 1 if a is less than b, 0 otherwise.
        """
        a, b = self._pop_nums(2)
        self._push_bool(a < b)

    def _op_gt(self):
        """
        OP_GREATERTHAN | 0xa0
        Returns 1 if a is greater than b, 0 otherwise.
        """
        a, b = self._pop_nums(2)
        self._push_bool(a > b)

    def _op_leq(self):
        """
        OP_LESSTHANOREQUAL | 0xa1
        Returns 1 if a is less than or equal to b, 0 otherwise.
        """
        a, b = self._pop_nums(2)
        self._push_bool(a <= b)

    def _op_geq(self):
        """
        OP_GREATERTHANOREQUAL | 0xa2
        Returns 1 if a is greater than or equal to b, 0 otherwise.
        """
        a, b = self._pop_nums(2)
        self._push_bool(a >= b)

    def _op_min(self):
        """
        OP_MIN | 0xa3
        Returns the smaller of a and b.
        """
        a, b = self._pop_nums(2)
        self.stack.push(min(a, b).bytes)

    def _op_max(self):
        """
        OP_MAX | 0xa4
        Returns the larger of a and b.
        """
        a, b = self._pop_nums(2)
        self.stack.push(max(a, b).bytes)

    def _op_within(self):
        """
        OP_WITHIN | 0xa5
        Returns 1 if x is within the specified range (left-inclusive), 0 otherwise.
        """
        _max, _min, num = self._pop_nums(3)
        self._push_bool(_min <= num < _max)

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

        NOTE: If taproot = true we use Schnorr signatures instead of ECDSA
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

        NOTE: If Taproot = True, this OP_CODE is disabled
        """
        pass

    def _op_checkmultisigverify(self):
        """
        OP_CHECKMULTISIGVERIFY |  0xaf
        Same as OP_CHECKMULTISIG, but OP_VERIFY is executed afterward.

        NOTE: If Taproot = True, this OP_CODE is disabled
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
        Used in Taproot. Replaces OP_CHECKMULTISIG and OP_CHECKMULTISIGVERIFY
        """
        pass

    def _op_invalidopcode(self):
        """
        OP_INVALIDOPCODE | 0xff - Represents an invalid opcode.
        """
        return False


class ScriptParser:

    @staticmethod
    def parse_script(script: bytes) -> list:
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
