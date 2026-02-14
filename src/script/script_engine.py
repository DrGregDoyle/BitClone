"""
The ScriptEngine class
"""
import json
from dataclasses import replace, dataclass
from io import BytesIO

from src.core.byte_stream import get_stream, read_stream, read_little_int
from src.core.exceptions import ScriptEngineError
from src.core.opcodes import OPCODES
from src.cryptography import sha256
from src.script.context import ExecutionContext
from src.script.opcode_map import OPCODE_MAP
from src.script.parser import to_asm
from src.script.script_types import ScriptPubKey, ScriptSig, P2SH_Key, P2WPKH_Key, P2PKH_Key, P2WSH_Key, P2TR_Key
from src.script.signature_engine import SignatureEngine
from src.script.stack import BitStack, BitNum
from src.tx.tx import Witness

__all__ = ["ScriptEngine"]

_OP = OPCODES()
op_verify = OPCODE_MAP[0x69]


@dataclass(slots=True)
class Instruction:
    opcode: int  # numeric opcode value
    raw: bytes  # exact bytes as they appear in the script
    is_push: bool  # True for OP_PUSH* opcodes
    push_data: bytes | None = None

    def to_dict(self):
        return {
            "opcode": _OP.get_name(self.opcode),
            "opcode_num": self.opcode,
            "opcode_hex": hex(self.opcode),
            "raw": self.raw.hex(),
            "is_push": self.is_push,
            "push_data": self.push_data.hex() if self.push_data else ""
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


class ScriptEngine:

    def __init__(self):
        self.stack = BitStack()
        self.alt_stack = BitStack()
        self.ops_log = []
        self.sig_engine = SignatureEngine()

    def clear_stacks(self):
        self.stack.clear()
        self.alt_stack.clear()
        self.ops_log = []

    def _read_instructions(self, stream: BytesIO) -> Instruction | None:
        """
        Read a single instruction (opcode + any pushdata) from the stream.
        Returns None at end of stream.
        """
        opcode_byte = stream.read(1)
        if not opcode_byte:
            return None

        opcode = opcode_byte[0]

        # OP_PUSHBYTES_n: 0x01..0x4b
        if 0x01 <= opcode <= 0x4b:
            data = read_stream(stream, opcode)
            raw = opcode_byte + data
            return Instruction(opcode=opcode, raw=raw, is_push=True, push_data=data)
        # OP_PUSHDATA1
        if opcode == 0x4c:
            length = read_little_int(stream, 1)
            data = read_stream(stream, length)
            raw = opcode_byte + length.to_bytes(1, "little") + data
            return Instruction(opcode=opcode, raw=raw, is_push=True, push_data=data)
        # OP_PUSHDATA2
        if opcode == 0x4d:
            length = read_little_int(stream, 2)
            data = read_stream(stream, length)
            raw = opcode_byte + length.to_bytes(2, "little") + data
            return Instruction(opcode=opcode, raw=raw, is_push=True, push_data=data)
        # OP_PUSHDATA4
        if opcode == 0x4e:
            length = read_little_int(stream, 4)
            data = read_stream(stream, length)
            raw = opcode_byte + length.to_bytes(4, "little") + data
            return Instruction(opcode=opcode, raw=raw, is_push=True, push_data=data)

        # Non-push opcodes: single byte
        return Instruction(opcode=opcode, raw=opcode_byte, is_push=False, push_data=None)

    def _handle_conditionals(self, opcode: int, stream: BytesIO, ctx: ExecutionContext):
        """
        Handle OP_IF (0x63) and OP_NOTIF (0x64) with proper branching logic.
        Reads stream until OP_ELSE or OP_ENDIF, validates structure, and executes appropriate branch.
        """
        # Validate opcode
        if opcode not in [0x63, 0x64]:  # OP_IF, OP_NOTIF
            raise ScriptEngineError(f"Invalid opcode for conditional handling: {opcode:#x}")

        # Pop condition from stack
        condition = self.stack.pop()

        # Determine if condition is true
        # For OP_IF: execute if condition is true (non-empty, non-zero)
        # For OP_NOTIF: execute if condition is false (empty or zero)
        condition_met = self._stack_value_is_true(condition)
        if opcode == 0x64:  # OP_NOTIF
            condition_met = not condition_met

        # Read and parse the conditional block structure
        if_branch, else_branch = self._parse_conditional_block(stream)

        # Determine which branch to execute
        if condition_met:
            branch_to_execute = if_branch
        else:
            branch_to_execute = else_branch

        # Execute the selected branch
        return self.execute_script(branch_to_execute, ctx)

    def _parse_conditional_block(self, stream: BytesIO) -> tuple[bytes, bytes]:
        """
        Parse the conditional block structure from the stream.
        Returns (if_branch, else_branch) as bytes.
        Raises ScriptEngineError if OP_ENDIF is missing.
        """
        if_branch = BytesIO()
        else_branch = BytesIO()
        current_branch = if_branch

        depth = 1  # Track nested conditionals
        found_endif = False

        while depth > 0:
            instr = self._read_instructions(stream)
            if instr is None:
                raise ScriptEngineError("Missing OP_ENDIF: reached end of script without closing conditional")

            opcode = instr.opcode

            # Handle nested conditionals
            if opcode in (0x63, 0x64):  # OP_IF, OP_NOTIF
                depth += 1
                # Nested IF/NOTIF live inside the current branch
                current_branch.write(instr.raw)

            elif opcode == 0x67:  # OP_ELSE
                if depth == 1:
                    # This ELSE belongs to the top-level IF/NOTIF:
                    # switch branches but do NOT write OP_ELSE into either branch.
                    current_branch = else_branch
                    continue
                else:
                    # ELSE for a nested conditional, keep it in the branch
                    current_branch.write(instr.raw)

            elif opcode == 0x68:  # OP_ENDIF
                depth -= 1
                if depth == 0:
                    # Matching ENDIF for our top-level conditional; we stop here
                    found_endif = True
                    # Do NOT write this ENDIF into any branch
                    break
                else:
                    # ENDIF for a nested conditional, keep it in the branch
                    current_branch.write(instr.raw)

            else:
                # All other instructions (including all pushdata variants)
                # are already fully encoded in instr.raw.
                current_branch.write(instr.raw)

        if not found_endif:
            raise ScriptEngineError("Missing OP_ENDIF: conditional block not properly closed")

        return if_branch.getvalue(), else_branch.getvalue()

    def _handle_signatures(self, opcode: int, ctx: ExecutionContext):
        """
        0xab -- 0xba
        """
        # Parse signature type
        match opcode:
            # OP_CHECKSIG
            case 0xac:
                self._handle_checksig(ctx)
            # # OP_CHECKSIGVERIFY
            # case 0xad:
            #     self._handle_checksig(ctx)
            #     verified = op_verify(self.stack)
            #     if not verified:
            #         raise ScriptEngineError("Script failed OP_VERIFY call in OP_CHECKSIGVERIFY")
            # OP_CHECKMULTISIG
            case 0xae:
                self._handle_multisig(ctx)
            case _:
                raise ScriptEngineError(f"Unhandled signature opcode: {opcode}")

    def _stack_value_is_true(self, v: bytes) -> bool:
        """
        Bitcoin truthiness: false iff the ScriptNum value is 0.
        """
        # Empty is false
        if v == b'':
            return False

        # Interpret as ScriptNum; zero is false, non-zero is true.
        return BitNum.from_bytes(v).value != 0

    def _compute_sighash(self, ctx: ExecutionContext, script_code: bytes, sighash_num: int) -> bytes:
        """
        Compute the appropriate sighash for the current context (legacy / segwit / tapscript).
        """
        tx = ctx.tx
        utxo = ctx.utxo
        input_index = ctx.input_index

        if tx is None or utxo is None:
            raise ScriptEngineError("Missing context elements for sighash computation")

        # Tapscript (script-path Taproot)
        if getattr(ctx, "tapscript", False):
            utxos = ctx.utxo_list if getattr(ctx, "utxo_list", None) else [utxo]
            return self.sig_engine.get_taproot_sighash(
                tx=tx,
                input_index=input_index,
                utxos=utxos,
                ext_flag=1,
                sighash_num=sighash_num,
                leaf_hash=ctx.merkle_root,
            )

        # Segwit v0 (P2WPKH / P2WSH)
        if getattr(ctx, "is_segwit", False):
            return self.sig_engine.get_segwit_sighash(
                tx=tx,
                input_index=input_index,
                amount=utxo.amount,
                scriptpubkey=script_code,
                sighash_num=sighash_num,
            )

        # Legacy
        return self.sig_engine.get_legacy_sighash(
            tx=tx,
            input_index=input_index,
            scriptpubkey=script_code,
            sighash_num=sighash_num,
        )

    def _verify_sig(self, ctx: ExecutionContext, pubkey: bytes, der_sig: bytes, message_hash: bytes) -> bool:
        """
        Verify a single signature given the current script context.
        """
        # Tapscript uses Schnorr over x-only pubkeys.
        if getattr(ctx, "tapscript", False):
            return self.sig_engine.verify_schnorr_sig(
                xonly_pubkey=pubkey,
                msg=message_hash,
                sig=der_sig,
            )

        # Legacy + segwit v0 use ECDSA.
        return self.sig_engine.verify_ecdsa_sig(
            signature=der_sig,
            message=message_hash,
            public_key=pubkey,
        )

    def _handle_checksig(self, ctx: ExecutionContext):
        # Get context elements
        tx = ctx.tx
        utxo = ctx.utxo
        input_index = ctx.input_index

        # Validate
        if tx is None or utxo is None:
            raise ScriptEngineError("Missing context elements for OP_CHECKSIG")

        # Pop pubkey and signature
        pubkey, sig = self.stack.popitems(2)

        # Signature should be DER-encoded with sighash num
        if len(sig) < 1:
            raise ScriptEngineError("Signature stack item too short for OP_CHECKSIG")

        der_sig = sig[:-1]
        sighash_num = sig[-1]

        # Use script_code from context if available (for P2SH), otherwise use scriptpubkey
        script_code = ctx.script_code if getattr(ctx, "script_code", None) else utxo.scriptpubkey

        # Compute sighash based on context (legacy/segwit/tapscript)
        message_hash = self._compute_sighash(ctx, script_code, sighash_num)

        # Verify signature (ECDSA or Schnorr)
        signature_verified = self._verify_sig(ctx, pubkey, der_sig, message_hash)

        # Push result
        self.stack.pushbool(signature_verified)

    def _handle_multisig(self, ctx: ExecutionContext):
        """
        OP_CHECKMULTISIG:
            1) pop n, then pop that number of public keys
            2) pop m, then pop that number of signatures
            3) compare each signature with the corresponding public key
        """
        # Step 1: Extract values
        pubkeynum = self.stack.popnum()
        pubkeys = [self.stack.pop() for _ in range(pubkeynum)]
        signum = self.stack.popnum()
        sigs = [self.stack.pop() for _ in range(signum)]
        empty_byte = self.stack.pop()

        # Validate
        if empty_byte != b'':
            raise ScriptEngineError("Missing NULLDUMMY at bottom of stack for OP_CHECKMULTISIG")

        # Step 2: Initialize indexes
        sig_index = 0
        key_index = 0
        matches = 0

        # Use script_code from context if available (for P2SH), otherwise use scriptpubkey
        script_code = ctx.script_code if hasattr(ctx, 'script_code') and ctx.script_code else ctx.utxo.scriptpubkey

        # Step 3: Try to match signatures to public keys
        while sig_index < len(sigs) and key_index < len(pubkeys):
            sig = sigs[sig_index]
            pub = pubkeys[key_index]

            # Signature should be DER-encoded with sighash num
            der_sig = sig[:-1]
            sighash_num = sig[-1]
            message_hash = self._compute_sighash(ctx, script_code, sighash_num)

            if self.sig_engine.verify_ecdsa_sig(signature=der_sig, message=message_hash, public_key=pub):
                matches += 1
                sig_index += 1

            key_index += 1  # always advance key_index

        # Push bool
        self.stack.pushbool(matches == len(sigs))

    def validate_segwit(self, scriptpubkey: ScriptPubKey, ctx: ExecutionContext) -> bool:
        """
        For use with P2WPKH and P2WSH
        """
        # Clear stacks
        self.clear_stacks()

        # Get WitnessField from context
        tx = ctx.tx
        input_index = ctx.input_index
        witness_field: Witness = tx.witness[input_index]
        utxo = ctx.utxo

        # Find type
        is_p2wpkh = False
        is_p2wsh = False
        is_p2tr = False

        if P2WPKH_Key.matches(scriptpubkey.script):
            is_p2wpkh = True
        if P2WSH_Key.matches(scriptpubkey.script):
            is_p2wsh = True
        if P2TR_Key.matches(scriptpubkey.script):
            is_p2tr = True

        # TODO: Add validation here for ScriptPubKey type for mandatory spend fields

        # Handle P2WPKH
        if is_p2wpkh:
            # Validation
            if len(witness_field.items) != 2:
                raise ScriptEngineError("Expected 2 stackitems for P2WPKH Witness")

            # Push Signature and public key to stack
            sig = witness_field.items[0]
            pubkey = witness_field.items[1]
            self.stack.push(sig)
            self.stack.push(pubkey)

            # Get pubkeyhash from ScriptPubKey and create P2PKH script
            pubkeyhash = scriptpubkey.script[2:]
            p2pkh_script = P2PKH_Key.from_pubkeyhash(pubkeyhash)

            # Execute the P2PKH script
            self.execute_script(p2pkh_script.script, ctx)

        # Handle P2WSH
        if is_p2wsh:
            stackitems = len(witness_field.items)
            # Validation
            if stackitems < 2:
                raise ScriptEngineError("Need at least 1 signature and 1 script for P2WSH")

            # Script
            script = witness_field.items[-1]
            # Hash script
            hashed_script = sha256(script)
            # Compare to Scriptpubkey
            pubkeyhash = scriptpubkey.script[2:]

            # Return False if hashed script != pubkeyhash
            if pubkeyhash != hashed_script:
                self.ops_log.append("P2WSH Script fails pubkeyhash validation")
                return False

            # Push items to Witness field in reverse order
            sig_list = witness_field.items[:-1][::-1]
            self.stack.pushlist(sig_list)

            # Execute the P2WSH script
            self.execute_script(script, ctx)

        # Handle P2TR
        if is_p2tr:
            # Sort into key-path or spend-path
            stackitems = len(witness_field.items)
            if stackitems == 1:
                # Key-path
                sig = witness_field.items[0]
                if len(sig) == 65:
                    # Get hash_type
                    hash_type = sig[-1]
                    sig = sig[:-1]
                else:
                    hash_type = 0

                tweaked_pubkey = scriptpubkey.script[2:]
                sighash = self.sig_engine.get_taproot_sighash(
                    tx=tx,
                    input_index=input_index,
                    utxos=[utxo],
                    sighash_num=hash_type
                )
                valid_sig = self.sig_engine.verify_schnorr_sig(tweaked_pubkey, msg=sighash, sig=sig)
                return valid_sig
            else:
                # Script-path | All witness elements are datapushes
                witness_items = list(witness_field.items)  # shallow copy
                control_block = witness_items.pop(-1)  # Last element of witness is control block
                leaf_script = witness_items.pop(-1)  # second last element is leaf script

                # TODO: Add control_block validation methods

                # Push remaining witness items and execute leaf_script
                self.stack.pushlist(witness_items)
                self.execute_script(leaf_script, ctx)

        # Validate the stack
        return self.validate_stack()

    def validate_script_pair(self, scriptpubkey: ScriptPubKey, scriptsig: ScriptSig, ctx: ExecutionContext = None) -> \
            bool:
        """
        We validate the scriptsig + scriptpubkey against the given ExecutionContext. For use with legacy signatures
        """
        # Proceed based on P2SH
        if not P2SH_Key.matches(scriptpubkey.script):
            # Not P2SH, validate combined script pairs
            return self.validate_script(scriptsig.script + scriptpubkey.script, ctx)

        # Assuming P2SH operation
        # ctx.is_p2sh = True
        self.clear_stacks()  # Clear stacks here for P2SH

        # Execute scriptSig
        self.execute_script(scriptsig.script, ctx)

        # Before processing the scriptpubkey we copy the redeem_script
        redeem_script = self.stack.top

        # Execute scriptpubkey
        self.execute_script(scriptpubkey.script, ctx)

        # Stack should now have 1 on top of stack and signatures for redeem script
        if not op_verify(self.stack):  # op_verify
            self.ops_log.append("Script Invalid -- P2SH ScriptPubKey failed OP_EQUAL check for HASH160")
            return False

        # Handle P2WPKH
        if P2WPKH_Key.matches(redeem_script):
            # Get elements
            tx = ctx.tx
            witness = tx.witness[ctx.input_index]
            witsig = witness.items[0]
            witkey = witness.items[1]

            # Remove P2WPKH key and push signature and pubkey
            self.stack.push(witsig)
            self.stack.push(witkey)

            # Get pubkeyhash from P2SH-P2WPKH_Sig and create P2PKH script
            pubkeyhash = scriptsig.script[3:]
            p2pkh_script = P2PKH_Key.from_pubkeyhash(pubkeyhash)

            # Execute the P2PKH script
            self.execute_script(p2pkh_script.script, ctx)
        else:
            # Execute redeem script
            new_ctx = replace(ctx, script_code=redeem_script)  # ExecutionContext is immutable.
            self.execute_script(redeem_script, new_ctx)
        return self.validate_stack()

    def execute_script(self, script: bytes | BytesIO, ctx: ExecutionContext = None) -> bool:
        """
        We only execute the given script with the accompanying ExecutionContext. We do NOT manage or validate the
        stacks.
        """

        # Get script as byte stream
        stream = get_stream(script) if isinstance(script, bytes) else script

        # Read script
        valid_script = True
        while valid_script:

            # Handle data
            instr = self._read_instructions(stream)

            # Handle end of stream
            if instr is None:
                self.ops_log.append("--- END OF SCRIPT ---")
                break

            opcode = instr.opcode

            # Get opcode name
            opcode_name = _OP.get_name(opcode)
            self.ops_log.append(opcode_name)

            # --- Data pushes (all OP_PUSHBYTES / PUSHDATA*) ---
            if instr.is_push:
                # push raw data onto the stack
                self.stack.push(instr.push_data or b"")
                # log the pushed data as hex for debugging
                self.ops_log.append((instr.push_data or b"").hex())
                continue

            # --- OP_0 ---
            if opcode == 0:
                self.stack.pushbool(False)
                continue

            # --- OP_n (1..16) ---
            if 0x51 <= opcode <= 0x60:
                num = opcode - 0x50
                self.stack.push(BitNum(num).to_bytes())
                continue

            # --- OP_NOP ---
            if opcode == 0x61:
                continue

            # --- Conditionals: OP_IF, OP_NOTIF ---
            if opcode in (0x63, 0x64):
                valid_script = self._handle_conditionals(opcode, stream, ctx)
                continue

            # --- OP_RETURN (unconditional failure) ---
            if opcode == 0x6a:
                valid_script = False
                continue

            # --- Signature-related opcodes that don't call OP_VERIFY ---
            if opcode in [0xac, 0xae]:
                self._handle_signatures(opcode, ctx)
                continue

            # --- All remaining opcodes: dispatch via OPCODE_MAP ---
            func = OPCODE_MAP[opcode]

            # Main stack and Alt stack ops (OP_TOALTSTACK, OP_FROMALTSTACK)
            if opcode in (0x6b, 0x6c):
                func(self.stack, self.alt_stack)

            # Verify-style ops that return a bool and may end script (OP_VERIFY, OP_EQUALVERIFY, etc.)
            elif opcode in (0x69, 0x88, 0x9d):
                valid_script = func(self.stack)

            # Verify-style ops for verifying a signature (OP_CHECKSIGVERIFY, OP_CHECKMULTISIGVERIFY, etc...)
            elif opcode in [0xad, 0xaf]:
                self._handle_checksig(ctx) if opcode == 0xad else self._handle_multisig(ctx)
                valid_script = op_verify(self.stack)

            else:
                # Normal stack-only opcodes
                func(self.stack)

        # --- Get data after OP_RETURN
        if not valid_script:
            self.ops_log.append("Invalid script")
            self.ops_log.append(to_asm(script))

        # Return script status
        return valid_script

    def validate_script(self, script: bytes, ctx: ExecutionContext = None) -> bool:
        # Clear stacks
        self.clear_stacks()

        # Execute script
        if not self.execute_script(script, ctx):
            return False  # Triggered invalid script

        # Logging
        print("BEFORE VALIDATING STACK", end="\n====\n")
        print(f"MAIN STACK: {self.stack.to_json()}")

        # Validate stack
        return self.validate_stack()

    def validate_stack(self) -> bool:
        """
        Called at the end of the script engine. Return False if any of the following are True:
            - Stack is empty
            - Only element left on the stack is OP_0 (aka b'')
            - More than one element left on the stack
            - Script exits prematurely (e.g OP_RETURN)
        """
        if self.stack.height != 1:
            # Handles empty stack and more than one element left on stack
            return False
        last_element = self.stack.pop()  # Also clears stack for next execution
        return self._stack_value_is_true(last_element)


# --- TESTING --- #

if __name__ == "__main__":
    sep = "---" * 80

    print("--- CONDITIONAL SCRIPT TESTING ---  ")

    engine = ScriptEngine()
    test_script = bytes.fromhex("00645268")
    result = engine.validate_script(test_script)
    print(f"TEST SCRIPT: {to_asm(test_script)}")
    print(f"SCRIPT ENGINE STACK RESULT: {result}")
