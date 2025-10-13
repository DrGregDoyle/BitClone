"""
The ScriptEngine class
"""

from io import BytesIO

from src.core.byte_stream import get_stream
from src.core.exceptions import ScriptEngineError
from src.core.opcodes import OPCODES
from src.script.context import ExecutionContext
from src.script.opcode_map import OPCODE_MAP
from src.script.scriptpubkey import ScriptPubKey, P2PK_Key
from src.script.scriptsig import ScriptSig, P2PK_Sig
from src.script.signature_engine import SignatureEngine, SigHash, SignatureContext
from src.script.stack import BitStack

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

        print(f"DER SIG: {der_sig.hex()}")
        print(f"SIGHASH TYPE: SIGHASH_{SigHash(sighash_num).name}")

        # Get legacy sighash
        sig_ctx = SignatureContext(tx=tx, input_index=input_index, sighash_type=sighash_num,
                                   script_code=utxo.scriptpubkey)
        message_hash = self.sig_engine.get_legacy_sighash(sig_ctx)
        signature_verified = self.sig_engine.verify_ecdsa_sig(der_sig, message_hash, pubkey)
        self.stack.pushbool(signature_verified)

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
from src.tx.tx import Transaction
from src.tx.utxo import UTXO

if __name__ == "__main__":
    # LMAB ELEMENTS:

    # Transaction - contains the ScriptSig
    test_tx = Transaction.from_bytes(bytes.fromhex(
        "01000000019d7a3553c3faec3d88d18b36ec3bfcdf00c7639ea161205a02e7fc9a1a25b61d0100000049483045022100c219a522e65ca8500ebe05a70d5a49d840ccc15f2afa4ee9df783f06b2a322310220489a46c37feb33f52c586da25c70113b8eea41216440eb84771cb67a67fdb68c01ffffffff0200f2052a010000001976a914e32acf8e6718a32029dc395cca1e0ac45c33f14188ac00c817a8040000004341049464205950188c29d377eebca6535e0f3699ce4069ecd77ffebfbd0bcf95e3c134cb7d2742d800a12df41413a09ef87a80516353a2f0a280547bb5512dc03da8ac00000000"))
    print(f"TEST TX: {test_tx.to_json()}")

    # UTXO - References the tx containing the scriptpubkey, e.g, the TxOutput being spent
    test_utxo = UTXO(txid=bytes.fromhex("1db6251a9afce7025a2061a19e63c700dffc3bec368bd1883decfac353357a9d")[::-1],
                     vout=1, amount=25000000000, scriptpubkey=bytes.fromhex(
            "41049464205950188c29d377eebca6535e0f3699ce4069ecd77ffebfbd0bcf95e3c134cb7d2742d800a12df41413a09ef87a80516353a2f0a280547bb5512dc03da8ac"),
                     block_height=140496)

    test_ctx = ExecutionContext(tx=test_tx, utxo=test_utxo, input_index=0)

    _test_p2pk_key = P2PK_Key.from_bytes(bytes.fromhex(
        "41049464205950188c29d377eebca6535e0f3699ce4069ecd77ffebfbd0bcf95e3c134cb7d2742d800a12df41413a09ef87a80516353a2f0a280547bb5512dc03da8ac"))
    _test_p2pk_sig = P2PK_Sig.from_bytes(bytes.fromhex(
        "483045022100c219a522e65ca8500ebe05a70d5a49d840ccc15f2afa4ee9df783f06b2a322310220489a46c37feb33f52c586da25c70113b8eea41216440eb84771cb67a67fdb68c01"))
    print(f"P2PK KEY: {_test_p2pk_key.to_asm()}")
    print(f"P2PK SIG: {_test_p2pk_sig.to_asm()}")
    engine = ScriptEngine()
    pair_validated = engine.validate_script_pair(_test_p2pk_key, _test_p2pk_sig, test_ctx)
    print(f"P2PK Script Validated: {pair_validated}")
