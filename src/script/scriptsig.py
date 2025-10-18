"""
The ScriptSig class and its children
"""

import json
from abc import ABC, abstractmethod

from src.core import ScriptSigError, SCRIPT
from src.script.parser import to_asm

__all__ = ["P2PK_Sig", "P2PKH_Sig", "ScriptSig", 'P2MS_Sig', "P2SH_Sig"]

# --- OPCODES --- #
OP_PUSHBYTES_33 = b'\x21'
OP_PUSHBYTES_65 = b'\x41'
OP_CHECKSIG = b'\xac'


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


def parse_scriptsig(scriptsig_bytes: bytes) -> ScriptSig:
    """
    We read in the bytes and return one of the above ScriptSig, or empty object if it doesn't match.
    """
    # P2PK
    try:
        p2pk = P2PK_Sig.from_bytes(scriptsig_bytes)
        return p2pk
    except ScriptSigError:
        print("ScriptSig does not match p2pk format")
        pass

    # P2PKH
    try:
        p2pkh = P2PKH_Sig.from_bytes(scriptsig_bytes)
        return p2pkh
    except ScriptSigError:
        print("ScriptSig does not match p2pkh format")
        pass

    # P2MS
    try:
        p2ms = P2MS_Sig.from_bytes(scriptsig_bytes)
        return p2ms
    except ScriptSigError:
        print("ScriptSig does not match p2ms format")
        pass

    # P2SH
    try:
        p2sh = P2SH_Sig.from_bytes(scriptsig_bytes)
        return p2sh
    except ScriptSigError:
        print("ScriptSig does not match p2sh format")
        pass

    return ScriptSig()


# --- TESTING --- #
if __name__ == "__main__":
    # p2pkh_bytes = bytes.fromhex(
    #     "483045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1037952ce26e91e02205aa5f8f88f29bb4ad5808ebc12abfd26bd791256f367b04c6d955f01f28a7724012103f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31")
    # test_p2pkh = P2PKH_Sig.from_bytes(p2pkh_bytes)
    # print(f"TEST P2PKH_Sig: {test_p2pkh.to_asm()}")

    p2ms_bytes = bytes.fromhex(
        "00483045022100af204ef91b8dba5884df50f87219ccef22014c21dd05aa44470d4ed800b7f6e40220428fe058684db1bb2bfb6061bff67048592c574effc217f0d150daedcf36787601483045022100e8547aa2c2a2761a5a28806d3ae0d1bbf0aeff782f9081dfea67b86cacb321340220771a166929469c34959daf726a2ac0c253f9aff391e58a3c7cb46d8b7e0fdc4801")
    test_p2ms = P2MS_Sig.from_bytes(p2ms_bytes)
    print(f"TEST P2MS: {test_p2ms.to_asm()}")

    p2sh_bytes = bytes.fromhex(
        "00473044022100d0ed946330182916da16a6149cd313a4b1a7b41591ee52fb3e79d64e36139d66021f6ccf173040ef24cb45c4db3e9c771c938a1ba2cf8d2404416f70886e360af401475121022afc20bf379bc96a2f4e9e63ffceb8652b2b6a097f63fbee6ecec2a49a48010e2103a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c052ae")
    test_p2sh = P2SH_Sig.from_bytes(p2sh_bytes)
    print(f"TEST P2SH: {test_p2sh.to_asm()}")
