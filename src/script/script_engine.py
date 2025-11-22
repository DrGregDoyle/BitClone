"""
The ScriptEngine class
"""

from io import BytesIO

from src.core.byte_stream import get_stream
from src.core.exceptions import ScriptEngineError
from src.core.opcodes import OPCODES
from src.cryptography import sha256
from src.data.taproot import Leaf, Tree, get_tweak, TweakPubkey
from src.script.context import ExecutionContext, SignatureContext
from src.script.opcode_map import OPCODE_MAP
from src.script.scriptpubkey import ScriptPubKey, P2SH_Key, P2WPKH_Key, P2PKH_Key, P2WSH_Key, P2TR_Key
from src.script.scriptsig import ScriptSig
from src.script.signature_engine import SignatureEngine
from src.script.stack import BitStack, BitNum
from src.tx.tx import WitnessField, Transaction
from src.tx.utxo import UTXO

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

    def _handle_signatures(self, opcode: int, stream: BytesIO, ctx: ExecutionContext):
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
        sig_ctx = SignatureContext(tx=tx, input_index=input_index, sighash_type=sighash_num,
                                   script_code=script_code, amount=utxo.amount)

        # Taproot
        if ctx.tapscript:
            sig_ctx.amounts = [utxo.amount]
            sig_ctx.prev_scriptpubkeys = [script_code]
            sig_ctx.merkle_root = ctx.merkle_root
            sig_ctx.ext_flag = 1
            message_hash = self.sig_engine.get_taproot_sighash(sig_ctx)
        # Segwit but not taproot
        elif ctx.is_segwit:
            message_hash = self.sig_engine.get_segwit_sighash(sig_ctx)
        # Legacy
        else:
            message_hash = self.sig_engine.get_legacy_sighash(sig_ctx)
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

            # Get legacy sighash
            sig_ctx = SignatureContext(tx=ctx.tx, input_index=ctx.input_index, sighash_type=sighash_num,
                                       script_code=script_code, amount=ctx.utxo.amount)

            # Handle type of signature
            if ctx.is_segwit:
                message_hash = self.sig_engine.get_segwit_sighash(sig_ctx)
            else:
                message_hash = self.sig_engine.get_legacy_sighash(sig_ctx)

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
                sig_ctx = SignatureContext(
                    tx=tx,
                    input_index=input_index,
                    amount=utxo.amount,
                    script_code=scriptpubkey.script,
                    sighash_type=hash_type,
                    annex=None,
                    ext_flag=0
                )

                tweaked_pubkey = scriptpubkey.script[2:]
                sighash = self.sig_engine.get_taproot_sighash(sig_ctx)
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
        ctx.is_p2sh = True
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
            ctx.script_code = redeem_script
            # Execute redeem script
            self.execute_script(redeem_script, ctx)
        return self.validate_stack()

        # combined_script = scriptsig.script + scriptpubkey.script
        # return self.execute_script(combined_script, ctx)

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

            # Handle checksigs
            elif 0xab <= opcode <= 0xba:
                self._handle_signatures(opcode, stream, ctx)
            # Get function for operation
            else:
                func = OPCODE_MAP[opcode]
                # --  Call func with various inputs depending on opcode
                # Main stack and Alt Stack
                if opcode in [0x6b, 0x6c]:
                    func(self.stack, self.alt_stack)
                else:
                    func(self.stack)

        # --- LOGGING --- #
        print("--- VALIDATE STACK ---")
        print(f"MAIN STACK: {self.stack.to_json()}")
        print(f"OPS LOG: {self.ops_log}")

    def validate_script(self, script: bytes, ctx: ExecutionContext) -> bool:
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

    print("--- P2TR SCRIPT-PATH (Tree) SPEND --- ")

    # --- ScriptPubKey and Taproot Tree

    xonly_pubkey = bytes.fromhex("924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329")
    leaf_scripts = [
        bytes.fromhex("5187"),
        bytes.fromhex("5287"),
        bytes.fromhex("5387"),
        bytes.fromhex("5487"),
        bytes.fromhex("5587")
    ]
    leaves = [Leaf(s) for s in leaf_scripts]
    tree = Tree(leaf_scripts)
    tweak = get_tweak(xonly_pubkey, tree.merkle_root)
    tweak_pubkey = TweakPubkey(xonly_pubkey, tree.merkle_root)

    test_p2tr_pubkey = P2TR_Key(xonly_pubkey, leaf_scripts)
    known_scriptpubkey = bytes.fromhex("5120979cff99636da1b0e49f8711514c642f640d1f64340c3784942296368fadd0a5")
    test_p2tr_utxo = UTXO(
        txid=bytes.fromhex("ec7b0fdfeb2c115b5a4b172a3a1cf406acc2425229c540d40ec752d893aac0d7")[::-1],
        vout=0,
        amount=10000,
        scriptpubkey=test_p2tr_pubkey.script,
        block_height=863632
    )

    # --- Known tx
    known_tx = Transaction.from_bytes(bytes.fromhex(
        "02000000000101d7c0aa93d852c70ed440c5295242c2ac06f41c3a2a174b5a5b112cebdf0f7bec0000000000ffffffff01260100000000000016001492b8c3a56fac121ddcdffbc85b02fb9ef681038a03010302538781c0924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a33291324300a84045033ec539f60c70d582c48b9acf04150da091694d83171b44ec9bf2c4bf1ca72f7b8538e9df9bdfd3ba4c305ad11587f12bbfafa00d58ad6051d54962df196af2827a86f4bde3cf7d7c1a9dcb6e17f660badefbc892309bb145f00000000"))

    test_ctx = ExecutionContext(
        tx=known_tx,
        input_index=0,
        utxo=test_p2tr_utxo,
        amount=test_p2tr_utxo.amount,
        tapscript=True,
        is_segwit=True
    )

    engine = ScriptEngine()
    script_validated = engine.validate_segwit(test_p2tr_pubkey, test_ctx)

    # --- LOGGING
    print(f"TREE: {tree.to_json()}")
    print(f"MERKLE ROOT: {tree.merkle_root.hex()}")
    print(f"TWEAK: {tweak.hex()}")
    print(f"TWEAK PUBKEY: {tweak_pubkey.tweaked_pubkey.x_bytes().hex()}")
    print(f"SCRIPT PUBKEY: {test_p2tr_pubkey.to_json()}")
    print(f"KNOWN TX: {known_tx.to_json()}")
    print(f"PUBKEYS AGREE: {test_p2tr_pubkey.script == known_scriptpubkey}")
    print(f"VALID SCRIPT: {script_validated}")
