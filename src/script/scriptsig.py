"""
The ScriptSig class and its children
"""

from abc import ABC, abstractmethod

from src.core import ScriptSigError, SCRIPT
from src.script.parser import to_asm

__all__ = ["P2PK", "P2PKH", "ScriptSig", 'P2MS']

# --- OPCODES --- #
OP_PUSHBYTES_33 = b'\x21'
OP_PUSHBYTES_65 = b'\x41'
OP_CHECKSIG = b'\xac'


class ScriptSig(ABC):
    """
    Base class for scriptSigs
    """
    script = None

    def pushdata(self, item: bytes):
        """
        For a given item, we return the corresponding OP code + item to push the item within Script
        """
        item_len = len(item)
        # OP_PUSHBYTES
        if 0x01 <= item_len <= 0x4b:
            return item_len.to_bytes(1, "little") + item
        # OP_PUSHDATA1
        elif item_len <= 0xff:
            return b'\x4c' + item_len.to_bytes(1, "little") + item
        # OP_PUSHDATA2
        elif item_len <= 0xffff:
            return b'\x4d' + item_len.to_bytes(2, "little") + item
        # OP_PUSHDATA4
        elif item_len <= 0xffffffff:
            return b'\x4d' + item_len.to_bytes(4, "little") + item
        else:
            raise ScriptSigError("Item of incorrect length to be pushed on stack.")

    def to_asm(self):
        return to_asm(self.script)


class P2PK(ScriptSig):
    """
    Script = OP_PUSHBYTES + signature

    ECDSA signatures are always ≤74 bytes (71-73 bytes DER + 1 byte sighash),
    so we never need OP_PUSHDATA opcodes.
    """

    def __init__(self, sig: bytes):
        self.script = self.pushdata(sig)

    @classmethod
    @abstractmethod
    def from_bytes(cls, scriptsig: bytes):
        leading_byte = scriptsig[0]
        actual_siglen = len(scriptsig[1:])

        # Check if it's a direct push (OP_PUSHBYTES)
        if 0x01 <= leading_byte <= 0x4b and actual_siglen == leading_byte:
            return cls(scriptsig[1:])

        raise ScriptSigError(
            f"Incorrect format for P2PK ScriptSig (expected length {leading_byte}, got {actual_siglen})")


class P2PKH(ScriptSig):
    """
    Script = OP_PUSHBYTES + signature + OP_PUSHBYTES + public_key

    NOTES
        -pubkey can be either compressed or uncompressed (33 bytes or 65 bytes, resp)
        -Whatever form the pubkey uses in the ScriptSig needs to be the same one which generates the pubkeyhash in
        the ScriptPubKey
    """

    def __init__(self, sig: bytes, pubkey: bytes):
        # Verify pubkey length
        if len(pubkey) not in SCRIPT.PUBKEY_LENS:
            raise ScriptSigError(f"Given public key not of allowable length: {SCRIPT.PUBKEY_LENS}")

        # Construct: <sig_len> <sig> <pubkey_len> <pubkey>
        self.script = self.pushdata(sig) + self.pushdata(pubkey)  # Will raise errors if lengths incorrect

    @classmethod
    def from_bytes(cls, scriptsig: bytes):
        # Parse signature
        sig_len = scriptsig[0]
        if not (0x01 <= sig_len <= 0x4b):
            raise ScriptSigError(f"Invalid signature length indicator: {sig_len}")

        sig = scriptsig[1:1 + sig_len]
        if len(sig) != sig_len:
            raise ScriptSigError(f"Signature length mismatch (expected {sig_len}, got {len(sig)})")

        # Parse pubkey
        offset = 1 + sig_len
        if offset >= len(scriptsig):
            raise ScriptSigError("ScriptSig truncated (missing pubkey)")

        pubkey_len = scriptsig[offset]
        pubkey = scriptsig[offset + 1:offset + 1 + pubkey_len]

        if len(pubkey) != pubkey_len:
            raise ScriptSigError(f"Pubkey length mismatch (expected {pubkey_len}, got {len(pubkey)})")

        return cls(sig, pubkey)


class P2MS(ScriptSig):
    """
    Pay 2 multisig, takes in list of signatures and returns OP_PUSHBYTES ahead of each signature.
    We include an additional OP_0 due to OP_CHECKMULTISIG bug. (BIP-147)
    P2MS | OP_0 + #signatures * (OP_PUSHBYTES + SIGNATURE)
    """

    def __init__(self, signatures: list):
        self.script = b'\x00'  # BIP-147
        for sig in signatures:
            self.script += self.pushdata(sig)

    @classmethod
    def from_bytes(cls, scriptsig: bytes):
        # BIP147
        leading_byte = scriptsig[0]
        if leading_byte != 0:
            raise ScriptSigError("MultiSig ScriptSig missing necessary NULLDUMMY value")

        signatures = []
        scriptsig = scriptsig[1:]
        while True:
            # Extract all signatures
            ss_len = scriptsig[0]
            signatures.append(scriptsig[1:1 + ss_len])
            scriptsig = scriptsig[1 + ss_len:]
            if scriptsig == b'':
                break
        return cls(signatures)


# --- TESTING --- #
if __name__ == "__main__":
    # p2pkh_bytes = bytes.fromhex(
    #     "483045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1037952ce26e91e02205aa5f8f88f29bb4ad5808ebc12abfd26bd791256f367b04c6d955f01f28a7724012103f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31")
    # test_p2pkh = P2PKH.from_bytes(p2pkh_bytes)
    # print(f"TEST P2PKH: {test_p2pkh.to_asm()}")

    p2ms_bytes = bytes.fromhex(
        "00493046022100a41a9015c847f404a14fcc81bf711ee2ce57583987948d54ebe540aafca97e0d022100d4e30d1ca42f77df8290b8975aa8fc0733d7c0cfdd5067ca516bac6c4012b47a01")
    test_p2ms = P2MS.from_bytes(p2ms_bytes)
    print(f"TEST P2MS: {test_p2ms.to_asm()}")
