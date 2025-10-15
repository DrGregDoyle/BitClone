"""
The ScriptEngine class
"""

from io import BytesIO

from src.core.byte_stream import get_stream
from src.core.exceptions import ScriptEngineError
from src.core.opcodes import OPCODES
from src.script.context import ExecutionContext
from src.script.opcode_map import OPCODE_MAP
from src.script.scriptpubkey import ScriptPubKey, P2MS_Key
from src.script.scriptsig import ScriptSig, P2MS_Sig
from src.script.signature_engine import SignatureEngine, SignatureContext
from src.script.stack import BitStack, BitNum
from src.tx.tx import Transaction
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

        # Get legacy sighash
        sig_ctx = SignatureContext(tx=tx, input_index=input_index, sighash_type=sighash_num,
                                   script_code=utxo.scriptpubkey)
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

        # Step 3: Try to match signatures to public keys
        while sig_index < len(sigs) and key_index < len(pubkeys):
            sig = sigs[sig_index]
            pub = pubkeys[key_index]

            # Signature should be DER-encoded with sighash num
            der_sig = sig[:-1]
            sighash_num = sig[-1]

            # Get legacy sighash
            sig_ctx = SignatureContext(tx=ctx.tx, input_index=ctx.input_index, sighash_type=sighash_num,
                                       script_code=ctx.utxo.scriptpubkey)
            message_hash = self.sig_engine.get_legacy_sighash(sig_ctx)

            if self.sig_engine.verify_ecdsa_sig(signature=der_sig, message=message_hash, public_key=pub):
                matches += 1
                sig_index += 1

            key_index += 1  # always advance key_index

        # Push bool
        self.stack.pushbool(matches == len(sigs))

    def _op_verify(self):
        top = self.stack.pop()
        return top != b''  # Returns False whenever top of stack is b''

    def validate_script_pair(self, scriptpubkey: ScriptPubKey, scriptsig: ScriptSig, ctx: ExecutionContext = None):
        """
        We validate the scriptsig + scriptpubkey against the given ExecutionContext
        """
        combined_script = scriptsig.script + scriptpubkey.script
        return self.validate_script(combined_script, ctx)

    def validate_script(self, script: bytes, ctx: ExecutionContext = None):
        # Prep Stacks
        self.clear_stacks()

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
    # P2MS - Setup
    test_p2ms_sig = P2MS_Sig.from_bytes(bytes.fromhex(
        "00483045022100af204ef91b8dba5884df50f87219ccef22014c21dd05aa44470d4ed800b7f6e40220428fe058684db1bb2bfb6061bff67048592c574effc217f0d150daedcf36787601483045022100e8547aa2c2a2761a5a28806d3ae0d1bbf0aeff782f9081dfea67b86cacb321340220771a166929469c34959daf726a2ac0c253f9aff391e58a3c7cb46d8b7e0fdc4801"))
    test_p2ms_key = P2MS_Key.from_bytes(bytes.fromhex(
        "524104d81fd577272bbe73308c93009eec5dc9fc319fc1ee2e7066e17220a5d47a18314578be2faea34b9f1f8ca078f8621acd4bc22897b03daa422b9bf56646b342a24104ec3afff0b2b66e8152e9018fe3be3fc92b30bf886b3487a525997d00fd9da2d012dce5d5275854adc3106572a5d1e12d4211b228429f5a7b2f7ba92eb0475bb14104b49b496684b02855bc32f5daefa2e2e406db4418f3b86bca5195600951c7d918cdbe5e6d3736ec2abf2dd7610995c3086976b2c0c7b4e459d10b34a316d5a5e753ae"))

    print(f"P2MS SIG: {test_p2ms_sig.to_json()}")
    print(f"P2MS KEY: {test_p2ms_key.to_json()}")

    # Context
    current_tx = Transaction.from_bytes(
        bytes.fromhex(
            "010000000110a5fee9786a9d2d72c25525e52dd70cbd9035d5152fac83b62d3aa7e2301d58000000009300483045022100af204ef91b8dba5884df50f87219ccef22014c21dd05aa44470d4ed800b7f6e40220428fe058684db1bb2bfb6061bff67048592c574effc217f0d150daedcf36787601483045022100e8547aa2c2a2761a5a28806d3ae0d1bbf0aeff782f9081dfea67b86cacb321340220771a166929469c34959daf726a2ac0c253f9aff391e58a3c7cb46d8b7e0fdc4801ffffffff0180a21900000000001976a914971802edf585cdbc4e57017d6e5142515c1e502888ac00000000")
    )
    current_input_index = 0
    test_utxo = UTXO(
        # Reverse display txid
        txid=bytes.fromhex("581d30e2a73a2db683ac2f15d53590bd0cd72de52555c2722d9d6a78e9fea510")[::-1],
        vout=0,
        amount=1690000,
        scriptpubkey=test_p2ms_key.script,
        block_height=442241
    )

    p2ms_context = ExecutionContext(
        tx=current_tx,
        input_index=current_input_index,
        utxo=test_utxo
    )

    # Validate
    engine = ScriptEngine()
    script_valid = engine.validate_script_pair(test_p2ms_key, test_p2ms_sig, p2ms_context)
    print(f"Validate P2MS Script Pair: {script_valid}")
