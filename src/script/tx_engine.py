"""
A method for constructing and signing transactions
"""
from src.core import SignatureError
from src.cryptography import hash160
from src.data import PubKey
from src.script.parser import to_asm
from src.script.scriptpubkey import P2PKH_Key, P2SH_Key, P2MS_Key
from src.script.scriptsig import P2PK_Sig, P2PKH_Sig, P2MS_Sig, P2SH_Sig
from src.script.signature_engine import SignatureEngine, SigHash
from src.tx import Transaction


class TxEngine:

    def __init__(self, sig_engine: SignatureEngine | None = None):
        self.sig_engine = sig_engine or SignatureEngine()


# --- DER-ENCODED SIGNATURES --- #
def get_legacy_sig(private_key: bytes | int, tx: Transaction, input_index: int, scriptpubkey: bytes, sighash_num: int
= 1) -> bytes:
    """
    Given a private key, a Transaction, input_index, a Scriptpubkey and sighash value, we return the DER-Encoded
    ECDSA signature with appended Sighash byte
    """
    # --- Step 1: Configure engine and private key
    sig_engine = SignatureEngine()
    privkey_int = int.from_bytes(private_key, "big") if isinstance(private_key, bytes) else private_key

    # --- Step 2: Get the legacy sighash
    legacy_sighash = sig_engine.get_legacy_sighash(
        tx=tx, input_index=input_index, scriptpubkey=scriptpubkey, sighash_num=sighash_num
    )

    # --- Step 3: Sign the legacy sighash and get the DER-encoding of the signature
    der_encoding = sig_engine.get_ecdsa_sig(privkey_int, legacy_sighash)

    # --- Step 4: Append sighash byte to der-encoded signature and return
    return der_encoding + SigHash(sighash_num).to_byte()


def get_segwit_sig(private_key: bytes | int, tx: Transaction, input_index: int, amount: int, scriptpubkey: bytes,
                   sighash_num: int = 1) -> bytes:
    """
    We return the DER-encoded signature using the segwit sighash algorithm
    """
    # --- Step 1: Configure SignatureEngine and format variables
    sig_engine = SignatureEngine()
    privkey_int = int.from_bytes(private_key, "big") if isinstance(private_key, bytes) else private_key

    # --- Step 2: Get segwit sighash
    segwit_sighash = sig_engine.get_segwit_sighash(tx, input_index, amount, scriptpubkey, sighash_num)

    # --- Step 3: Sign the segwit sighash and get the DER-encoding of the signature
    der_encoding = sig_engine.get_ecdsa_sig(privkey_int, segwit_sighash)

    # --- Step 4: Append sighash byte to der-encoded signature and return
    return der_encoding + SigHash(sighash_num).to_byte()


# --- SIGN TRANSACTION TYPES --- #

def sign_p2pk_tx(private_key: bytes | int, tx: Transaction, input_index: int, scriptpubkey: bytes, sighash_num: int
= 1) -> Transaction:
    """
    We return the Tx with a P2Pk scriptsig
    """
    sig = get_legacy_sig(private_key, tx, input_index, scriptpubkey, sighash_num)
    scriptsig = P2PK_Sig(sig)
    tx.inputs[input_index].scriptsig = scriptsig.script
    return tx


def sign_p2pkh_tx(private_key: bytes | int, tx: Transaction, input_index: int, scriptpubkey: bytes, sighash_num: int
= 1) -> Transaction:
    """
    We get the signature for the given transaction and insert it into the scriptsig of the Transaction input at the
    given input_index
    """
    # Get sig
    sig = get_legacy_sig(private_key, tx, input_index, scriptpubkey, sighash_num)
    # Get pubkey
    pubkey = PubKey(private_key)
    scriptsig = P2PKH_Sig(sig, pubkey.compressed())
    tx.inputs[input_index].scriptsig = scriptsig.script
    return tx


def sign_p2ms_tx(private_keys: list[bytes | int], tx: Transaction, input_index: int, scriptpubkey: bytes,
                 sighash_num: int = 1) -> Transaction:
    """
    Pay to MultiScript. Will create the P2MS sighash
    """
    # Get signatures for all private keys
    signatures = [get_legacy_sig(privkey, tx, input_index, scriptpubkey, sighash_num) for privkey in private_keys]
    # Create ScriptSig
    p2ms_scriptsig = P2MS_Sig(signatures)
    # Add scriptsig to tx and return
    tx.inputs[input_index].scriptsig = p2ms_scriptsig.script
    return tx


def sign_p2sh_tx(private_key: bytes | int, tx: Transaction, input_index: int, scriptpubkey: bytes,
                 redeem_script: bytes, sighash_num: int = 1) -> Transaction:
    """
    We create the P2SH ScriptSig for a P2SH ScriptPubKey with only one signature
    """
    # --- Validation
    if not P2SH_Key.matches(scriptpubkey):
        raise SignatureError("Given ScriptPubKey doesn't match P2SH format")

    # --- Get legacy signature
    legacy_sig = get_legacy_sig(private_key, tx, input_index, redeem_script, sighash_num)

    # --- Create P2SH ScriptSig
    p2sh_scriptsig = P2SH_Sig(legacy_sig, redeem_script)

    # Add scriptsig to tx and return
    tx.inputs[input_index].scriptsig = p2sh_scriptsig.script
    return tx


def sign_p2sh_p2ms_tx(
        private_keys: list[bytes | int],
        tx: Transaction,
        input_index: int,
        scriptpubkey: bytes,
        redeem_script: bytes,
        sighash_num: int = 1,
) -> Transaction:
    """
    Sign a P2SH-wrapped multisig (P2SH-P2MS) input.
    """
    # --- Validation
    # Verify ScriptPubKey is a P2SH
    if not P2SH_Key.matches(scriptpubkey):
        raise SignatureError("Given ScriptPubKey doesn't match P2SH format")
    # Verify redeem script is P2MS
    if not P2MS_Key.matches(redeem_script):
        raise SignatureError("Given redeem script doesn't match P2MS format")
    if not P2SH_Key(hash_data=hash160(redeem_script)).script == scriptpubkey:
        raise SignatureError("Redeem script does not hash to given scriptpubkey")

    # 1) Get legacy signatures using redeem_script as the scriptCode
    signatures = [
        get_legacy_sig(privkey, tx, input_index, redeem_script, sighash_num)
        for privkey in private_keys
    ]

    # 2) Build P2SH ScriptSig: OP_0 <sig1> ... <sigm> <redeem_script>
    p2sh_scriptsig = P2SH_Sig(signatures, redeem_script)

    # 3) Attach to tx and return
    tx.inputs[input_index].scriptsig = b'\x00' + p2sh_scriptsig.script  # Add OP_0 for P2MS nulldata bug
    return tx


# def sign_segwit_tx(
#         self,
#         tx: Transaction,
#         input_index: int,
#         script_code: bytes,
#         amount: int,
#         privkey: int | bytes,
#         sighash_num: int = 1
# ) -> Transaction:
#     """
#     The algorithm for signing a segwit transaction
#     """
#     # Setup
#     privkey_int = int.from_bytes(privkey, 'big') if isinstance(privkey, bytes) else privkey
#
#     # Validation
#     # TODO: Add validation here
#
#     # Step 1. Construct the preimage hash
#     ctx = SignatureContext(
#         tx=tx,
#         input_index=input_index,
#         sighash_type=sighash_num,
#         script_code=script_code,
#         amount=amount
#     )
#     preimage_hash = self.get_segwit_sighash(ctx)
#
#     # Step 2. Sign the preimage hash | method returns DER encoded signature
#     preimage_sig = self.get_ecdsa_sig(privkey_int, preimage_hash)
#
#     # Step 3. Append sighash type to der_sig
#     segwit_sig = preimage_sig + SigHash(sighash_num).to_byte()
#
#     # Step 4. Construct WitnessField = [signature, compressed public key]
#     cpk = PubKey(privkey_int).compressed()
#     witness_field = WitnessField(items=[segwit_sig, cpk])
#
#     # Step 5. Insert witness into the Tx
#     if not tx.witness:
#         tx.witness.append(witness_field)
#     else:
#         tx.witness[input_index] = witness_field
#     return tx

# def sign_taproot_keypath(
#         self,
#         tx: Transaction,
#         input_index: int,
#         script_code: bytes,
#         amount: int,
#         privkey: int | bytes,
#         sighash_num: int = 1,
#         aux_bytes: bytes = None
#
# ):
#     # Create signature context
#     ctx = SignatureContext(
#         tx=tx,
#         input_index=input_index,
#         sighash_type=sighash_num,
#         script_code=script_code,
#         amount=amount,
#         annex=None,
#         ext_flag=0
#     )
#
#     # Get sighash
#     taproot_sighash = self.get_taproot_sighash(ctx)
#     print(f"TAPROOT SIGHASH: {taproot_sighash.hex()}")
#
#     # Format privkey
#     privkey_int = int.from_bytes(privkey, "big") if isinstance(privkey, bytes) else privkey
#     print(f"PRIVKEY: {privkey_int.to_bytes(32, 'big').hex()}")
#
#     # Get signature
#     keypath_schnorr_sig = self.get_schnorr_sig(privkey_int, taproot_sighash, aux_bytes)
#     print(f'SCHNORR SIG: {keypath_schnorr_sig.hex()}')
#
#     # Validate schnorr sig
#     temp_pubkey = PubKey(privkey_int)
#     valid_sig = self.verify_schnorr_sig(temp_pubkey.x_bytes(), taproot_sighash, keypath_schnorr_sig)
#     print(f"VALID SIG: {valid_sig}")
#
#     # Create and add witness item | signature + sighash_byte
#     witness_item = keypath_schnorr_sig + SigHash(sighash_num).to_byte()
#     keypath_witness = WitnessField(items=[witness_item])
#
#     if tx.witness:
#         tx.witness[input_index] = keypath_witness
#     else:
#         tx.witness.append(keypath_witness)
#
#     # Return tx with withness signature element
#     return tx

# def sign_taproot_scriptpath(self, tx: Transaction, input_index: int, privkey: int | bytes, amount: int,
#                             xonly_pubkey: bytes, scripts: list[bytes], script_index: int = 0, sighash_type: int
#                             = 1,
#                             aux_rand: bytes = None) -> Transaction:
#     # --- Step 1: Get the P2TR ScriptPubKey and merkle root
#     p2tr_key = P2TR_Key(xonly_pubkey=xonly_pubkey, scripts=scripts)
#     merkle_root = get_unbalanced_merkle_root(scripts=scripts)
#
#     # --- Step 2: Construct the message sighash
#     ctx = SignatureContext(
#         tx=tx, input_index=input_index, sighash_type=sighash_type, ext_flag=1, amounts=[amount],
#         prev_scriptpubkeys=[p2tr_key.script], amount=amount, merkle_root=merkle_root
#     )
#     taproot_sighash = self.get_taproot_sighash(ctx)
#     print(f"TAPFOOT SIGHASH: {taproot_sighash.hex()}")
#
#     # --- Step 3: Sign the sighash using Schnorr signatures
#     privkey_int = int.from_bytes(privkey, "big") if isinstance(privkey, bytes) else privkey
#     taproot_sig = self.get_schnorr_sig(privkey_int, taproot_sighash, aux_rand)
#     print(f"SIGNATURE: {taproot_sig.hex()}")
#
#     # --- Step 4: Add the hash byte
#     taproot_sigand = taproot_sig + SigHash(sighash_type).to_byte()
#     print(f"SIGNATURE WITH HASH BYTE: {taproot_sigand.hex()}")
#
#     # --- Step 5: Get merkle path and control block
#     if len(scripts) > 1:
#         # Todo: Get merkle path here
#         merkle_path = b''
#     else:
#         merkle_path = b''
#     control_block = get_control_block(xonly_pubkey, merkle_root, merkle_path)
#
#     # --- Step 6: Get leaf script and create WitnessField
#     leaf_script = scripts[script_index]
#     witness = WitnessField(items=[taproot_sigand, leaf_script, control_block])
#     print(f"WITNESS: {witness.to_json()}")
#     print(f"WITNESS SERIALIZED: {witness.to_bytes().hex()}")
#
#     # --- Step 7: Add witness to witness list in tx and return it
#     tx.witness[input_index] = witness
#     return tx


# --- TESTING ---
if __name__ == "__main__":
    sep = "===" * 50
    print(" --- SIGNATURE TESTING --- ")

    known_privkey = bytes.fromhex("f94a840f1e1a901843a75dd07ffcc5c84478dc4f987797474c9393ac53ab55e6")
    test_pubkey = PubKey(known_privkey)

    test_scriptpubkey = P2PKH_Key(test_pubkey.compressed())

    unsigned_tx = Transaction.from_bytes(bytes.fromhex(
        "0100000001b7994a0db2f373a29227e1d90da883c6ce1cb0dd2d6812e4558041ebbbcfa54b0000000000ffffffff01983a0000000000001976a914b3e2819b6262e0b1f19fc7229d75677f347c91ac88ac00000000"))
    unsigned_copy = Transaction.from_bytes(unsigned_tx.to_bytes())
    signed_tx = sign_p2pkh_tx(known_privkey, unsigned_tx, 0, test_scriptpubkey.script)
    lmab_tx = Transaction.from_bytes(bytes.fromhex(
        "0100000001b7994a0db2f373a29227e1d90da883c6ce1cb0dd2d6812e4558041ebbbcfa54b000000006a473044022008f4f37e2d8f74e18c1b8fde2374d5f28402fb8ab7fd1cc5b786aa40851a70cb02201f40afd1627798ee8529095ca4b205498032315240ac322c9d8ff0f205a93a580121024aeaf55040fa16de37303d13ca1dde85f4ca9baa36e2963a27a1c0c1165fe2b1ffffffff01983a0000000000001976a914b3e2819b6262e0b1f19fc7229d75677f347c91ac88ac00000000"))

    # --- LOGGING
    print(f"PUBKEY: {test_pubkey.to_json()}")
    print(f"P2PKH SCRIPTPUBKEY: {test_scriptpubkey.to_json()}")
    print(f"UNSIGNED TX: {unsigned_copy.to_json()}")
    print(f"SIGNED TX: {signed_tx.to_json()}")
    print(f"LMAB TX: {lmab_tx.to_json()}")
    print(f"SIGNED SCRIPTSIG EQUAL TO LMAB SCRIPTSIG: {signed_tx.inputs[0].scriptsig == lmab_tx.inputs[0].scriptsig}")
    print(f"SIGNED SCIPT ASM: {to_asm(signed_tx.inputs[0].scriptsig)}")
    print(f"LMAB SCRIPT ASM: {to_asm(lmab_tx.inputs[0].scriptsig)}")
