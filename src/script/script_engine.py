"""
The ScriptEngine class
"""

from dataclasses import replace
from io import BytesIO

from src.core.byte_stream import get_stream
from src.core.exceptions import ScriptEngineError
from src.core.opcodes import OPCODES
from src.cryptography import sha256
from src.script.context import ExecutionContext
from src.script.opcode_map import OPCODE_MAP
from src.script.parser import to_asm
from src.script.script_types import ScriptPubKey, ScriptSig, P2SH_Key, P2WPKH_Key, P2PKH_Key, P2WSH_Key, P2TR_Key
from src.script.signature_engine import SignatureEngine
from src.script.stack import BitStack, BitNum
from src.tx.tx import WitnessField

__all__ = ["ScriptEngine"]

_OP = OPCODES()


class ScriptEngine:
    opcode_map = OPCODE_MAP
    opcode_names = _OP.get_code_dict()

    def __init__(self):
        self.stack = BitStack()
        self.alt_stack = BitStack()
        self.ops_log = []
        self.sig_engine = SignatureEngine()

    def clear_stacks(self):
        self.stack.clear()
        self.alt_stack.clear()
        self.ops_log = []

    def _read_opcode(self, stream: BytesIO):
        opcode_byte = stream.read(1)
        return int.from_bytes(opcode_byte, "little") if opcode_byte else None

    def _handle_pushdata(self, opcode: int, stream: BytesIO):
        # Validate
        if not 0x01 <= opcode <= 0x4b:
            raise TypeError("Opcode out of bounds for pushdata operation")
        data = stream.read(opcode)
        self.stack.push(data)
        # ops_log
        self.ops_log.append(data.hex())

    def _handle_pushdata_n(self, n, stream: BytesIO):
        n_bytes = stream.read(n)
        num = int.from_bytes(n_bytes, "little")
        data = stream.read(num)
        self.stack.push(data)
        # ops_log
        self.ops_log.extend([num, data.hex()])

    def _handle_signatures(self, opcode: int, ctx: ExecutionContext):
        """
        0xab -- 0xba
        """
        # Parse signature type
        match opcode:
            # OP_CODESEPARATOR
            case 0xab:
                print("OP_CODESEPARATOR")
            # OP_CHECKSIG
            case 0xac:
                self._handle_checksig(ctx)
            # OP_CHECKSIGVERIFY
            case 0xad:
                self._handle_checksig(ctx)
                verified = self._op_verify()
                if not verified:
                    raise ScriptEngineError("Script failed OP_VERIFY call in OP_CHECKSIGVERIFY")
            # OP_CHECKMULTISIG
            case 0xae:
                self._handle_multisig(ctx)
            case _:
                print(f"OPCODE: {opcode}")

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
        der_sig = sig[:-1]
        sighash_num = sig[-1]

        # Use script_code from context if available (for P2SH), otherwise use scriptpubkey
        script_code = ctx.script_code if hasattr(ctx, 'script_code') and ctx.script_code else utxo.scriptpubkey

        # Get sighash | Parse context to figure out what goes in the context
        # sig_ctx = SignatureContext(tx=tx, input_index=input_index, sighash_type=sighash_num,
        #                            script_code=script_code, amount=utxo.amount)

        # Taproot
        if ctx.tapscript:
            if ctx.utxo_list:
                utxos = ctx.utxo_list
            else:
                utxos = [utxo]

            # sig_ctx.amounts = [utxo.amount]
            # sig_ctx.prev_scriptpubkeys = [script_code]
            # sig_ctx.merkle_root = ctx.merkle_root
            # sig_ctx.ext_flag = 1
            message_hash = self.sig_engine.get_taproot_sighash(
                tx=tx, input_index=input_index, utxos=utxos, ext_flag=1, sighash_num=sighash_num,
                leaf_hash=ctx.merkle_root)
        # Segwit but not taproot
        elif ctx.is_segwit:
            message_hash = self.sig_engine.get_segwit_sighash(
                tx=tx,
                input_index=input_index,
                amount=utxo.amount,
                scriptpubkey=script_code,
                sighash_num=sighash_num
            )
        # Legacy
        else:
            message_hash = self.sig_engine.get_legacy_sighash(
                tx=tx, input_index=input_index, scriptpubkey=utxo.scriptpubkey, sighash_num=sighash_num
            )
        print(f"MESSAGE HASH: {message_hash.hex()}")
        if ctx.tapscript:
            signature_verified = self.sig_engine.verify_schnorr_sig(xonly_pubkey=pubkey, msg=message_hash, sig=der_sig)
        else:
            signature_verified = self.sig_engine.verify_ecdsa_sig(der_sig, message_hash, pubkey)
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

            # Handle type of signature
            if ctx.is_segwit:
                message_hash = self.sig_engine.get_segwit_sighash(tx=ctx.tx, input_index=ctx.input_index,
                                                                  amount=ctx.utxo.amount, scriptpubkey=script_code,
                                                                  sighash_num=sighash_num)
            else:
                message_hash = self.sig_engine.get_legacy_sighash(tx=ctx.tx, input_index=ctx.input_index,
                                                                  scriptpubkey=script_code, sighash_num=sighash_num)

            if self.sig_engine.verify_ecdsa_sig(signature=der_sig, message=message_hash, public_key=pub):
                matches += 1
                sig_index += 1

            key_index += 1  # always advance key_index

        # Push bool
        self.stack.pushbool(matches == len(sigs))

    def _op_verify(self) -> bool:
        top = self.stack.pop()
        return top != b''  # Returns False whenever top of stack is b''

    def validate_segwit(self, scriptpubkey: ScriptPubKey, ctx: ExecutionContext) -> bool:
        """
        For use with P2WPKH and P2WSH
        """
        # Clear stacks
        self.clear_stacks()

        # Get WitnessField from context
        tx = ctx.tx
        input_index = ctx.input_index
        witness_field: WitnessField = tx.witness[input_index]
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
                witness_items = witness_field.items
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
        print(f"REDEEM SCRIPT: {redeem_script.hex()}")

        # Execute scriptpubkey
        self.execute_script(scriptpubkey.script, ctx)

        # Stack should now have 1 on top of stack and signatures for redeem script
        if not self._op_verify():
            print("P2SH ScriptPubKey failed OP_EQUAL check for HASH160")
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

    def execute_script(self, script: bytes, ctx: ExecutionContext = None):
        """
        We only execute the given script with the accompanying ExecutionContext. We do NOT manage or validate the
        stacks.
        """

        # Get script as byte stream
        stream = get_stream(script)

        # Read script
        valid_script = True
        while valid_script:
            opcode = self._read_opcode(stream)

            # Handle end of stream
            if opcode is None:
                self.ops_log.append("--- END OF SCRIPT ---")
                break

            # Get opcode name
            opcode_name = _OP.get_name(opcode)
            self.ops_log.append(opcode_name)

            # Handle data
            if 0x01 <= opcode <= 0x4b:
                self._handle_pushdata(opcode, stream)

            # Handle pushdata_n
            elif 0x4c <= opcode <= 0x4e:
                match opcode:
                    case 0x4c:
                        n = 1
                    case 0x4d:
                        n = 2
                    case _:
                        n = 4
                self._handle_pushdata_n(n, stream)

            # Handle OP_num
            elif 0x51 <= opcode <= 0x60:
                num = opcode - 0x50
                self.stack.push(BitNum(num).to_bytes())

            # Handle OP_NOP
            elif opcode == 0x61:
                continue



            # Handle OP_RETURN or OP_VER
            elif opcode == 0x6a:
                valid_script = False
                continue

            # Handle checksigs
            elif 0xab <= opcode <= 0xba:
                self._handle_signatures(opcode, ctx)

            # Get function for operation
            else:
                func = OPCODE_MAP[opcode]
                # --  Call func with various inputs depending on opcode
                # Main stack and Alt Stack
                if opcode in [0x6b, 0x6c]:
                    func(self.stack, self.alt_stack)
                # Verify stack ops
                elif opcode in [0x69, 0x88, 0x9d]:
                    valid_script = func(self.stack)
                # OP_RETURN (no stack ops)
                elif opcode in [0x6a]:
                    valid_script = func()
                else:
                    func(self.stack)

        # --- Get data after OP_RETURN
        if not valid_script:
            self.ops_log.append("Invalid script")
            self.ops_log.append(to_asm(script))

        # # --- LOGGING --- #
        print("--- VALIDATE STACK ---")
        print(f"MAIN STACK: {self.stack.to_json()}")
        print(f"OPS LOG: {self.ops_log}")

    def validate_script(self, script: bytes, ctx: ExecutionContext = None) -> bool:
        # Clear stacks
        self.clear_stacks()

        # Execute script
        self.execute_script(script, ctx)

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
        return last_element != b''  # Return True if element is anything other than OP_0


# --- TESTING --- #

if __name__ == "__main__":
    sep = "---" * 80

    print("--- CONDITIONAL SCRIPT TESTING ---  ")

    engine = ScriptEngine()
    test_script = bytes.fromhex("514f61938b")
    result = engine.validate_script(test_script)
    print(f"TEST SCRIPT: {to_asm(test_script)}")
    print(f"SCRIPT ENGINE STACK RESULT: {result}")
