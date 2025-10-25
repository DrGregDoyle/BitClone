"""
The ScriptEngine class
"""

from io import BytesIO

from src.core.byte_stream import get_stream
from src.core.exceptions import ScriptEngineError
from src.core.opcodes import OPCODES
from src.script.context import ExecutionContext
from src.script.opcode_map import OPCODE_MAP
from src.script.scriptpubkey import ScriptPubKey, P2SH_Key, P2WPKH_Key, P2PKH_Key
from src.script.scriptsig import ScriptSig
from src.script.signature_engine import SignatureEngine, SignatureContext
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

        # Get sighash
        sig_ctx = SignatureContext(tx=tx, input_index=input_index, sighash_type=sighash_num,
                                   script_code=script_code, amount=utxo.amount)
        if ctx.is_segwit:
            message_hash = self.sig_engine.get_segwit_sighash(sig_ctx)
        else:
            message_hash = self.sig_engine.get_legacy_sighash(sig_ctx)
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
                                       script_code=script_code)
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

        # Find type
        if P2WPKH_Key.matches(scriptpubkey.script):
            is_p2wpkh = True
        else:
            is_p2wpkh = False

        # Handle P2WPKH
        if is_p2wpkh:
            # Get WitnessField from context
            tx = ctx.tx
            input_index = ctx.input_index
            witness_field: WitnessField = tx.witness[input_index]

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

            # Validate the stack
            return self.validate_stack()

        return True

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
    # P2WPKH
    test_p2wpkh_key = P2WPKH_Key.from_bytes(bytes.fromhex("0014841b80d2cc75f5345c482af96294d04fdd66b2b7"))
    witness_signature = bytes.fromhex(
        "3045022100c7fb3bd38bdceb315a28a0793d85f31e4e1d9983122b4a5de741d6ddca5caf8202207b2821abd7a1a2157a9d5e69d2fdba3502b0a96be809c34981f8445555bdafdb01")
    witness_pubkey = bytes.fromhex("03f465315805ed271eb972e43d84d2a9e19494d10151d9f6adb32b8534bfd764ab")
    test_witness = WitnessField(items=[witness_signature, witness_pubkey])
    # print(f"TEST WITNESS: {test_witness.to_json()}")

    # Known data:
    current_tx = Transaction.from_bytes(bytes.fromhex(
        "020000000001013aa815ace3c5751ee6c325d614044ad58c18ed2858a44f9d9f98fbcddad878c10000000000ffffffff01344d10000000000016001430cd68883f558464ec7939d9f960956422018f0702483045022100c7fb3bd38bdceb315a28a0793d85f31e4e1d9983122b4a5de741d6ddca5caf8202207b2821abd7a1a2157a9d5e69d2fdba3502b0a96be809c34981f8445555bdafdb012103f465315805ed271eb972e43d84d2a9e19494d10151d9f6adb32b8534bfd764ab00000000"
    ))
    # print(f"CURRENT TX: {current_tx.to_json()}")

    test_utxo = UTXO(
        # Reverse display bytes for txid
        txid=bytes.fromhex("c178d8dacdfb989f9d4fa45828ed188cd54a0414d625c3e61e75c5e3ac15a83a")[::-1],
        vout=0,
        amount=1083200,
        scriptpubkey=test_p2wpkh_key.script
    )

    p2wpkh_context = ExecutionContext(
        tx=current_tx,
        utxo=test_utxo,
        input_index=0,
        is_segwit=True,
        script_code=bytes.fromhex("841b80d2cc75f5345c482af96294d04fdd66b2b7")
    )

    engine = ScriptEngine()
    sig_validated = engine.validate_segwit(test_p2wpkh_key, p2wpkh_context)
    print(f"P2WPKH VALIDATED: {sig_validated}")
