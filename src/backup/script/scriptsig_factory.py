"""
The ScriptSig class that provides factory methods for different script types.

NOTES:
    -The ScripSig is the UNLOCKING code for a previous output
    -The ScriptSig is tied to particular ScriptPubKey on an output
    -ScriptSig is used to unlock legacy ScriptPubKey types, e.g: P2PK_Sig, P2PKH_Sig, P2MS, P2SH
"""
from src.backup.data import ScriptType
from src.backup.logger import get_logger
from src.backup.script.script_parser import ScriptParser
from src.backup.script.scriptpubkey_factory import ScriptPubKey

logger = get_logger(__name__)

__all__ = ["ScriptSigFactory"]


# --- SCRIPT SIG CLASS --- #
class ScriptSig:
    # --- COMMON OPCODES
    OP_0 = b'\x00'

    def __init__(self, script_type: ScriptType, *args):
        # Internals
        self._parser = ScriptParser()

        self.script_type = script_type

        # Map script types to their handler functions
        handlers = {
            ScriptType.P2PK_Sig: self._handle_p2pk,
            ScriptType.P2PKH_Sig: self._handle_p2pkh,
            ScriptType.P2MS: self._handle_p2ms,
            ScriptType.P2SH: self._handle_p2sh,
        }

        handler = handlers.get(self.script_type)

        if handler is None:
            raise ValueError(f"Unsupported script type: {self.script_type}")

        # Safely call the handler
        self.script = handler(*args)
        self.asm = self._parser.parse_script(self.script)

    # -- HELPERS

    def _pushdata(self, item: bytes) -> bytes:
        """
        For a given item, return the corresponding OP_CODES + Data for a datapush
        """
        length = len(item)
        if length <= 75:
            return length.to_bytes(1, "little") + item
        elif length <= 255:
            return b'\x4c' + length.to_bytes(1, "little") + item
        elif length <= 65535:
            return b'\x4d' + length.to_bytes(2, "little") + item
        else:
            return b'\x4e' + length.to_bytes(4, "little") + item

    # -- HANDLERS

    def _handle_p2pk(self, sig: bytes):
        """
        P2PK_Sig | OP_PUSHBYTES + SIGNATURE
        """
        return self._pushdata(sig)

    def _handle_p2pkh(self, sig: bytes, pubkey: bytes):
        """
        P2PKH_Sig | OP_PUSHBYTES + SIGNATURE + OP_PUSHBYTES + PUBKEY
        """
        return self._pushdata(sig) + self._pushdata(pubkey)

    def _handle_p2ms(self, signatures: list[bytes]):
        """
        P2MS | OP_0 + #signatures * (OP_PUSHBYTES + SIGNATURE)
        """
        script = self.OP_0
        for sig in signatures:
            script += self._pushdata(sig)
        return script

    def _handle_p2sh(self, items: list[bytes], redeem_script: ScriptPubKey):
        """
        P2SH | SIGNATURES + REDEEM SCRIPT
        Generic P2SH scriptsig: pushes all 'items' (args for redeem script), then pushes redeem script bytes.
        Handles multisig case with leading OP_0.
        """
        parts = []

        # If it's a multisig script, we expect a dummy OP_0 (i.e., b'')
        if redeem_script.script_type == ScriptType.P2MS:
            parts.append(b'\x00')  # OP_0
            items = items[1:]  # Don't mutate original list

        # Push args
        parts.extend([self._pushdata(item) for item in items])

        # Push redeem script
        parts.append(self._pushdata(redeem_script.script))

        return b''.join(parts)


class ScriptSigFactory:
    @staticmethod
    def p2pk(sig: bytes) -> ScriptSig:
        return ScriptSig(ScriptType.P2PK_Sig, sig)

    @staticmethod
    def p2pkh(sig: bytes, pubkey: bytes) -> ScriptSig:
        return ScriptSig(ScriptType.P2PKH_Sig, sig, pubkey)

    @staticmethod
    def p2ms(signatures: list[bytes]) -> ScriptSig:
        return ScriptSig(ScriptType.P2MS, signatures)

    @staticmethod
    def p2sh(items: list[bytes], redeem_script: ScriptPubKey, testnet: bool = False) -> ScriptSig:
        return ScriptSig(ScriptType.P2SH, items, redeem_script)


# --- TESTING
if __name__ == "__main__":
    ss_factory = ScriptSigFactory()
    test_uncompressed_pubkey = bytes.fromhex(
        "049464205950188c29d377eebca6535e0f3699ce4069ecd77ffebfbd0bcf95e3c134cb7d2742d800a12df41413a09ef87a80516353a2f0a280547bb5512dc03da8")
    p2pk_scriptsig = ss_factory.p2pk(test_uncompressed_pubkey)
    print(f"P2PK_Sig SCRIPTSIG: {p2pk_scriptsig.asm}")
