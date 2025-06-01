"""
The ScriptSig class that provides factory methods for different script types.
"""
from src.logger import get_logger
from src.script.script_parser import ScriptParser
from src.script.script_type import ScriptType
from src.script.scriptpubkey_factory import ScriptPubKey

logger = get_logger(__name__)

__all__ = ["ScriptSigFactory"]


# --- SCRIPT SIG CLASS --- #
class ScriptSig:
    # --- COMMON OPCODES
    OP_0 = b'\x00'

    def __init__(self, script_type: ScriptType, *args, testnet: bool = False):
        # Internals
        self._parser = ScriptParser()

        self.script_type = script_type
        self.testnet = testnet

        # Map script types to their handler functions
        handlers = {
            ScriptType.P2PK: self._handle_p2pk,
            ScriptType.P2PKH: self._handle_p2pkh,
            ScriptType.P2MS: self._handle_p2ms,
            ScriptType.P2SH: self._handle_p2sh,
            # ScriptType.P2WPKH: self._handle_p2wpkh,
            # ScriptType.P2WSH: self._handle_p2wsh,
            # ScriptType.P2TR: self._handle_p2tr,
            # ScriptType.CUSTOM: self._handle_custom
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
        P2PK | OP_PUSHBYTES + SIGNATURE
        """
        return self._pushdata(sig)

    def _handle_p2pkh(self, sig: bytes, pubkey: bytes):
        """
        P2PKH | OP_PUSHBYTES + SIGNATURE + OP_PUSHBYTES + PUBKEY
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
    def p2pk(sig: bytes, testnet: bool = False) -> ScriptSig:
        return ScriptSig(ScriptType.P2PK, sig, testnet=testnet)

    @staticmethod
    def p2pkh(sig: bytes, pubkey: bytes, testnet: bool = False) -> ScriptSig:
        return ScriptSig(ScriptType.P2PKH, sig, pubkey, testnet=testnet)

    @staticmethod
    def p2ms(signatures: list[bytes], testnet: bool = False) -> ScriptSig:
        return ScriptSig(ScriptType.P2MS, signatures, testnet=testnet)

    @staticmethod
    def p2sh(items: list[bytes], redeem_script: ScriptPubKey, testnet: bool = False) -> ScriptSig:
        return ScriptSig(ScriptType.P2SH, items, redeem_script, testnet=testnet)

    # Placeholder methods for future SegWit and Taproot support
    # @staticmethod
    # def p2wpkh(...): ...
    # @staticmethod
    # def p2wsh(...): ...
    # @staticmethod
    # def p2tr(...): ...
