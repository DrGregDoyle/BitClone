"""
The ScriptSig class and its children
"""

import json
from abc import ABC, abstractmethod

from src.core import ScriptSigError, SCRIPT, OPCODES
from src.script.parser import to_asm
from src.script.scriptpubkey import P2WPKH_Key

__all__ = ["P2PK_Sig", "P2PKH_Sig", "ScriptSig", 'P2MS_Sig', "P2SH_Sig", "P2SH_P2WPKH_Sig"]

# --- OPCODES --- #
OP_PUSHBYTES_33 = b'\x21'
OP_PUSHBYTES_65 = b'\x41'
OP_CHECKSIG = b'\xac'

_OP = OPCODES


class ScriptSig(ABC):
    """
    Base class for scriptSigs
    """
    script = None

    @classmethod
    @abstractmethod
    def from_bytes(cls, scriptsig: bytes):
        """All subclasses must implement this"""
        raise NotImplementedError("Missing from_bytes construction")

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

    def to_dict(self):
        return {
            "asm": json.loads(json.dumps(self.to_asm())),
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other):
        if isinstance(other, ScriptSig):
            return self.script == other.script
        raise ScriptSigError(f"Cannot equate ScriptSig and {type(other)}")


class P2PK_Sig(ScriptSig):
    """
    Script = OP_PUSHBYTES + signature

    ECDSA signatures are always ≤74 bytes (71-73 bytes DER + 1 byte sighash),
    so we never need OP_PUSHDATA opcodes.
    """

    def __init__(self, sig: bytes):
        self.script = self.pushdata(sig)

    @classmethod
    def from_bytes(cls, scriptsig: bytes):
        leading_byte = scriptsig[0]
        actual_siglen = len(scriptsig[1:])

        # Check if it's a direct push (OP_PUSHBYTES)
        if 0x01 <= leading_byte <= 0x4b and actual_siglen == leading_byte:
            return cls(scriptsig[1:])

        raise ScriptSigError(
            f"Incorrect format for P2PK_Sig ScriptSig (expected length {leading_byte}, got {actual_siglen})")


class P2PKH_Sig(ScriptSig):
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


class P2MS_Sig(ScriptSig):
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


class P2SH_Sig(ScriptSig):
    """
    The P2SH consists of two parts:
        -The signature(s) necessary to unlock the redeem script (which gets hash160'ed in the scriptpubkey)
        -A data push of the redeem script
    """

    def __init__(self, scriptsig: bytes | ScriptSig, redeem_script: bytes):
        scriptsig_bytes = scriptsig.script if isinstance(scriptsig, ScriptSig) else scriptsig
        self.script = scriptsig_bytes + self.pushdata(redeem_script)

    @classmethod
    def from_bytes(cls, scriptsig: bytes):
        if len(scriptsig) == 0:
            raise ScriptSigError("Empty P2SH ScriptSig")

        # Search backwards for the last valid OP_PUSHBYTES operation
        # The redeem script is the last data push in a P2SH scriptSig
        for i in range(len(scriptsig) - 1, -1, -1):
            push_len = scriptsig[i]

            # Check if this is a valid OP_PUSHBYTES opcode
            if 0x01 <= push_len <= 0x4b:
                # Check if the remaining bytes match the push length
                remaining_bytes = len(scriptsig) - (i + 1)

                if remaining_bytes == push_len:
                    # Found it! This is where the redeem script starts
                    redeem_script = scriptsig[i + 1:]
                    unlocking_scriptsig = scriptsig[:i]
                    return cls(unlocking_scriptsig, redeem_script)

        raise ScriptSigError("Could not find valid redeem script push in P2SH ScriptSig")


class P2SH_P2WPKH_Sig(ScriptSig):
    """
    ScriptPubKey = P2SH_Key
    But we unlock using both ScriptSig and WitnessField
    """
    OP_PUSHBYTES_22 = _OP.get_byte("OP_PUSHBYTES_22")

    def __init__(self, p2wpkh_key: bytes | P2WPKH_Key):
        self.script = self.OP_PUSHBYTES_22 + (p2wpkh_key.script if isinstance(p2wpkh_key, P2WPKH_Key) else p2wpkh_key)

    @classmethod
    def from_bytes(cls, scriptsig: bytes):
        # Check leading bytee
        lead_byte = scriptsig[0]

        if lead_byte == cls.OP_PUSHBYTES_22[0]:
            return cls(scriptsig[1:])
        raise ScriptSigError("Given data does not match P2SH-P2WPKH opcode syntax")


# --- TESTING --- #
if __name__ == "__main__":
    # P2SH-P2WPKH
    test_p2sh_p2wpkh_bytes = bytes.fromhex("16001402c8147af586cace7589672191bb1c790e9e9a72")
    test_key = P2SH_P2WPKH_Sig.from_bytes(test_p2sh_p2wpkh_bytes)
    print(f"P2SH-P2WPKH: {test_key.to_json()}")
