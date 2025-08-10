"""
Tests for verifying that various script_sig + script_pub_keys will evaluate to True in the script engine
"""

from random import randint
from secrets import randbits

from src.crypto import hash160, ORDER, generator_exponent
from src.data import compress_public_key, decode_der_signature, encode_der_signature
from src.data.utxo import UTXO
from src.data.varint import write_compact_size
from src.logger import get_logger
from src.script import ScriptValidator, SigHash, ScriptTree, Branch
from src.taproot import Taproot
from src.tx import Transaction, Input, Output, Witness, WitnessItem

logger = get_logger(__name__)


# -- HELPERS
def mutate_signature(signature: bytes, mode: str = "s") -> bytes:
    """
    Safely mutates a Bitcoin ECDSA signature (DER + sighash byte) for failure testing.

    Args:
        signature (bytes): Original signature (DER-encoded + sighash byte)
        mode (str): What to mutate:
            - "sighash": flips one bit in sighash byte
            - "s": modifies s slightly
            - "r": modifies r slightly

    Returns:
        bytes: Mutated signature (still DER-valid)
    """
    if len(signature) < 2:
        raise ValueError("Signature too short to mutate")

    sighash_byte = signature[-1]
    der_sig = signature[:-1]

    if mode == "sighash":
        new_sighash = sighash_byte ^ 0x01  # flip one bit
        return der_sig + bytes([new_sighash])

    r, s = decode_der_signature(der_sig)

    if mode == "r":
        r = (r + randint(1, 5)) % ORDER or 1
    elif mode == "s":
        s = (s + randint(1, 5)) % ORDER or 1
    else:
        raise ValueError(f"Unknown mode: {mode}")

    new_der = encode_der_signature(r, s)
    return new_der + bytes([sighash_byte])


def generate_keypair(xonly: bool = False):
    private_key = 0
    while not (1 <= private_key < ORDER):
        private_key = randbits(256)
    pubkey_point = generator_exponent(private_key)
    compressed_pubkey = compress_public_key(pubkey_point)
    return (private_key, compressed_pubkey) if not xonly else (private_key, compressed_pubkey[1:])


def make_utxo(pubkey_script: bytes, amount=50000, txid: bytes = None):
    _txid = txid if txid is not None else bytes.fromhex("f" * 64)
    return UTXO(
        txid=_txid,
        vout=0,
        amount=amount,
        script_pubkey=pubkey_script
    )


def build_tx(utxo: UTXO, output_script: bytes, segwit: bool = False):
    return Transaction(
        inputs=[Input(utxo.txid, utxo.vout, b'', sequence=0xffffffff)],
        outputs=[Output(49000, output_script)],
        segwit=segwit
    )


def build_witness(pubkey: bytes, signature: bytes) -> Witness:
    item1 = WitnessItem(signature)
    item2 = WitnessItem(pubkey)

    return Witness([item1, item2])


def add_scriptsig(tx: Transaction, script_sig: bytes, input_index: int = 0) -> Transaction:
    tx.inputs[input_index].script_sig = script_sig
    tx.inputs[input_index].script_sig_size = write_compact_size(len(script_sig))
    return tx


# -- TESTS
def test_p2pk(test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    """
    Minimal flow for P2PK test:
        - Generate keypair
        - Build P2PK scriptPubKey
        - Create UTXO with that scriptPubKey
        - Create tx spending that UTXO and sign it
        - Build scriptSig: push signature
        - Assert full script evaluates to True
    """
    script_engine.clear_stacks()
    test_db._clear_db()
    # 1. Generate keypair
    private_key, compressed_pubkey = generate_keypair()

    # 2. Get P2PK scriptPubKey
    p2pk_scriptpubkey = pubkey_factory.p2pk(compressed_pubkey)

    # 3. Create UTXO with that scriptPubKey
    p2pk_utxo = make_utxo(p2pk_scriptpubkey.script)
    test_db.add_utxo(p2pk_utxo)
    validator = ScriptValidator(test_db)

    # 4. Create transaction and sign it
    p2pk_tx = build_tx(p2pk_utxo, b'\x6a')  # OP_RETURN output
    legacy_sighash = sig_engine.get_legacy_sighash(p2pk_tx, 0, p2pk_scriptpubkey.script, 1)
    p2pk_signature = sig_engine.sign_message(private_key, legacy_sighash, 1)

    # 5. Build scriptSig and attach to tx
    p2pk_scriptsig = scriptsig_factory.p2pk(p2pk_signature)
    final_tx = add_scriptsig(p2pk_tx, p2pk_scriptsig.script)

    # 6. Modify input to reference utxo in db
    final_tx.inputs[0].txid = bytes.fromhex("f" * 64)

    # 7. Validate
    final_script = p2pk_scriptsig.script + p2pk_scriptpubkey.script
    asm = parser.parse_script(final_script)
    print(f"P2PK ASM: {asm}")
    assert validator.validate_utxo(final_tx, 0)
    assert script_engine.eval_script(
        script=final_script,
        tx=final_tx,
        input_index=0,
        utxo=p2pk_utxo), "p2pk scriptSig + scriptpubkey failed"

    # 7. Failure case: tampered signature
    bad_sig = mutate_signature(p2pk_signature, mode="s")
    bad_scriptsig = scriptsig_factory.p2pk(bad_sig)
    bad_tx = add_scriptsig(p2pk_tx, bad_scriptsig.script)
    bad_script = bad_scriptsig.script + p2pk_scriptpubkey.script
    assert not script_engine.eval_script(bad_script, bad_tx, utxo=p2pk_utxo,
                                         input_index=0), "p2pk tampered signature passed"


def test_p2pkh(test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    """
    Minimal flow for p2pkh test:
        -Generate pubkey
        -Build P2PKH scriptPubKey (will automatically hash160 the pubkey)
        -Create UTXO with that scriptPubKey
        -Create tx with that utxo and sign it
        -Build scriptSig: push signature, then pubkey
        -Assert full script evaluates to True
    """
    script_engine.clear_stacks()
    test_db._clear_db()
    # 1. Generate keypair
    private_key, compressed_pubkey = generate_keypair()

    # 2. Get p2pkh scriptpubkey
    p2pkh_scriptpubkey = pubkey_factory.p2pkh(compressed_pubkey)

    # 4. Create UTXO with that pubkey
    p2pkh_utxo = make_utxo(p2pkh_scriptpubkey.script)
    test_db.add_utxo(p2pkh_utxo)
    validator = ScriptValidator(test_db)

    # 5. Create tx with that utxo and sign it
    p2pkh_tx = build_tx(p2pkh_utxo, b'\x6a')  # OP_RETURN
    legacy_sighash = sig_engine.get_legacy_sighash(p2pkh_tx, 0, p2pkh_scriptpubkey.script, 1)
    p2pkh_signature = sig_engine.sign_message(private_key, legacy_sighash, 1)

    # 6. Build scriptsig and put it in the input
    p2pkh_scriptsig = scriptsig_factory.p2pkh(p2pkh_signature, compressed_pubkey)
    final_tx = add_scriptsig(p2pkh_tx, p2pkh_scriptsig.script)

    # 7. Modify input to reference utxo in db
    final_tx.inputs[0].txid = bytes.fromhex("f" * 64)

    # 8. Validate
    final_script = p2pkh_scriptsig.script + p2pkh_scriptpubkey.script
    asm = parser.parse_script(final_script)
    print(f"P2PKH ASM: {asm}")
    assert validator.validate_utxo(final_tx, 0), "p2pkh scriptSig + scriptpubkey failed"
    assert script_engine.eval_script(final_script, final_tx, utxo=p2pkh_utxo, input_index=0), "p2pkh scriptSig + " \
                                                                                              "scriptpubkey failed"


def test_p2ms(test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    """
    Flow for a P2MS test:
        - Generate 3 keypairs
        - Build a 2-of-3 multisig scriptPubKey
        - Create UTXO with that scriptPubKey
        - Create tx spending the UTXO and sign with 2 keys
        - Build scriptSig: OP_0 <sig1> <sig2>
        - Assert full script evaluates to True
    """
    script_engine.clear_stacks()
    test_db._clear_db()
    # 1. Generate 3 keypairs
    keys = [generate_keypair() for _ in range(3)]
    privkeys = [k[0] for k in keys]
    pubkeys = [k[1] for k in keys]  # compressed pubkeys

    # 2. Create 2-of-3 multisig script
    p2ms_scriptpubkey = pubkey_factory.p2ms(pubkeys, 2)  # pubkey_engine.p2ms(pubkeys, signum=2)

    # 3. Create UTXO and tx
    multisig_utxo = make_utxo(p2ms_scriptpubkey.script)
    test_db.add_utxo(multisig_utxo)
    multisig_tx = build_tx(multisig_utxo, b'\x6a')
    validator = ScriptValidator(test_db)

    # 4. Sign with first two keys
    legacy_sighash = sig_engine.get_legacy_sighash(multisig_tx, 0, p2ms_scriptpubkey.script, 1)
    sig1 = sig_engine.sign_message(privkeys[0], legacy_sighash, 1)
    sig2 = sig_engine.sign_message(privkeys[1], legacy_sighash, 1)

    # 5. Build scriptSig: OP_0 <sig1> <sig2>
    multisig_scriptsig = scriptsig_factory.p2ms([sig1, sig2])
    final_tx = add_scriptsig(multisig_tx, multisig_scriptsig.script)

    # 6. Modify input to reference utxo in db
    final_tx.inputs[0].txid = bytes.fromhex("f" * 64)

    # 7. Validate
    final_script = multisig_scriptsig.script + p2ms_scriptpubkey.script
    asm = parser.parse_script(final_script)
    logger.debug(f"P2MS ASM: {asm}")
    assert validator.validate_utxo(final_tx, 0), "p2ms 2-of-3 failed"


def test_p2sh_p2pk(test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    script_engine.clear_stacks()
    test_db._clear_db()
    # 1. Generate key
    privkey, pubkey = generate_keypair()

    # 2. Create redeem script
    redeem_scriptpubkey = pubkey_factory.p2pk(pubkey)
    p2sh_scriptpubkey = pubkey_factory.p2sh(redeem_script=redeem_scriptpubkey.script)

    # 3. Create UTXO
    utxo = make_utxo(p2sh_scriptpubkey.script)
    test_db.add_utxo(utxo)
    validator = ScriptValidator(test_db)

    # 4. Create tx and sign
    tx = build_tx(utxo, b'\x6a')
    legacy_sighash = sig_engine.get_legacy_sighash(tx, 0, p2sh_scriptpubkey.script, 1)
    sig = sig_engine.sign_message(privkey, legacy_sighash, 1)

    # 5. Build scriptsig
    scriptsig = scriptsig_factory.p2sh([sig], redeem_scriptpubkey)
    final_tx = add_scriptsig(tx, scriptsig.script)

    # 6. Modify input to reference utxo in db
    final_tx.inputs[0].txid = bytes.fromhex("f" * 64)

    # 7. Validate
    full_script = scriptsig.script + p2sh_scriptpubkey.script
    asm = parser.parse_script(full_script)
    print(f"P2SH(P2PK) ASM: {asm}")
    assert validator.validate_utxo(final_tx, 0), "P2SH(P2PK) failed"


def test_p2sh_p2pkh(test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    script_engine.clear_stacks()
    test_db._clear_db()
    # 1. Generate key
    privkey, pubkey = generate_keypair()

    # 2. Create redeem script
    redeem_scriptpubkey = pubkey_factory.p2pkh(pubkey)
    p2sh_scriptpubkey = pubkey_factory.p2sh(redeem_scriptpubkey.script)

    # 3. Create UTXO
    utxo = make_utxo(p2sh_scriptpubkey.script)
    test_db.add_utxo(utxo)
    validator = ScriptValidator(test_db)

    # 4. Create tx and sign
    tx = build_tx(utxo, b'\x6a')
    legacy_sighash = sig_engine.get_legacy_sighash(tx, 0, p2sh_scriptpubkey.script, 1)
    sig = sig_engine.sign_message(privkey, legacy_sighash, 1)

    # 5. Build scriptsig
    scriptsig = scriptsig_factory.p2sh([sig, pubkey], redeem_scriptpubkey)
    final_tx = add_scriptsig(tx, scriptsig.script)

    # 6. Modify input to reference utxo in db
    final_tx.inputs[0].txid = bytes.fromhex("f" * 64)

    # 7. Validate
    full_script = scriptsig.script + p2sh_scriptpubkey.script
    asm = parser.parse_script(full_script)
    print(f"P2SH(P2PKH) ASM: {asm}")
    assert validator.validate_utxo(final_tx, 0), "P2SH(P2PK) failed"


def test_p2sh_p2ms(test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    """
    Test P2SH-wrapped 2-of-3 multisig:
        - Create redeem script: OP_2 <pub1> <pub2> <pub3> OP_3 OP_CHECKMULTISIG
        - Wrap in P2SH scriptPubKey
        - Build scriptSig: OP_0 <sig1> <sig2> <redeem_script>
        - Validate via script_engine.validate_utxo
    """
    script_engine.clear_stacks()
    test_db._clear_db()
    # 1. Generate 3 keypairs
    keys = [generate_keypair() for _ in range(3)]
    privkeys = [k[0] for k in keys]
    pubkeys = [k[1] for k in keys]

    # 2. Create 2-of-3 redeem script and wrap it
    redeem_scriptpubkey = pubkey_factory.p2ms(pubkeys, signum=2)
    p2sh_scriptpubkey = pubkey_factory.p2sh(
        redeem_scriptpubkey.script)  # pubkey_engine.p2sh(redeem_script).scriptpubkey

    # 3. Create UTXO
    utxo = make_utxo(p2sh_scriptpubkey.script)
    test_db.add_utxo(utxo)
    validator = ScriptValidator(test_db)

    # 4. Build tx
    tx = build_tx(utxo, b'\x6a')

    # 5. Get signatures for 2 keys
    legacy_sighash = sig_engine.get_legacy_sighash(tx, 0, p2sh_scriptpubkey.script, 1)
    sig1 = sig_engine.sign_message(privkeys[0], legacy_sighash, 1)
    sig2 = sig_engine.sign_message(privkeys[1], legacy_sighash, 1)

    # 6. Build scriptSig: OP_0 <sig1> <sig2> <redeem_script>
    scriptsig = scriptsig_factory.p2sh([b'\x00', sig1, sig2], redeem_scriptpubkey)
    final_tx = add_scriptsig(tx, scriptsig.script)

    # 7. Modify input to reference utxo in db
    final_tx.inputs[0].txid = bytes.fromhex("f" * 64)

    # 8. Validate
    full_script = scriptsig.script + p2sh_scriptpubkey.script
    asm = parser.parse_script(full_script)
    print(f"P2SH(P2MS) ASM: {asm}")
    assert validator.validate_utxo(final_tx, 0), "P2SH(P2MS) failed"


def test_p2wpkh(test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    """
    Tests P2WPKH
    """
    script_engine.clear_stacks()
    test_db._clear_db()
    # 1. Generate keypair
    privkey, compressed_pubkey = generate_keypair()

    # 2. Get P2WPKH scriptpubkey
    p2wpkh_scriptpubkey = pubkey_factory.p2wpkh(compressed_pubkey)

    # 3. Create UTXO
    utxo = make_utxo(p2wpkh_scriptpubkey.script)
    test_db.add_utxo(utxo)
    validator = ScriptValidator(test_db)

    # 4. Create a tx
    tx = build_tx(utxo, b'\x6a')
    tx.segwit = True

    # 5. Get segwit signature
    pubkeyhash = hash160(compressed_pubkey)
    script_code = b'\x76\xa9\x14' + pubkeyhash + b'\x88\xac'
    segwit_sighash = sig_engine.get_segwit_sighash(tx, 0, script_code, utxo.amount, 1)
    segwit_sig = sig_engine.sign_message(privkey, segwit_sighash, 1)

    # 6. Create Witness object and insert into tx
    witness = build_witness(compressed_pubkey, segwit_sig)
    tx.witnesses = [witness]

    # 7. Validate
    print(f"P2WPKH SCRIPTPUBKEY: {parser.parse_script(p2wpkh_scriptpubkey.script)}")
    assert validator.validate_utxo(tx, 0), "P2WPKH Failed assertion"


def test_p2wsh_p2pk(test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    """
    Tests P2WSH (Pay to Witness Script Hash):
    - Create redeem script (e.g., simple p2pk)
    - Build P2WSH scriptPubKey
    - Create UTXO
    - Create tx spending it
    - Build witness: [sig, pubkey, redeem_script]
    - Validate
    """
    script_engine.clear_stacks()
    test_db._clear_db()

    # 1. Generate keypair
    privkey, compressed_pubkey = generate_keypair()

    # 2. Create a redeem script (simple p2pk)
    redeem_scriptpubkey = pubkey_factory.p2pk(compressed_pubkey)

    # 3. Create p2wsh scriptpubkey
    p2wsh_scriptpubkey = pubkey_factory.p2wsh(redeem_scriptpubkey.script)

    # 4. Create UTXO
    utxo = make_utxo(p2wsh_scriptpubkey.script)
    test_db.add_utxo(utxo)
    validator = ScriptValidator(test_db)

    # 5. Create transaction
    tx = build_tx(utxo, b'\x6a')
    tx.segwit = True

    # 6. Get segwit sighash (scriptCode is redeem script)
    segwit_sighash = sig_engine.get_segwit_sighash(tx, 0, redeem_scriptpubkey.script, utxo.amount, 1)
    segwit_sig = sig_engine.sign_message(privkey, segwit_sighash, 1)

    # 7. Build witness: [signature] | p2pk
    witness_items = [WitnessItem(segwit_sig), WitnessItem(redeem_scriptpubkey.script)]
    witness = Witness(witness_items)
    tx.witnesses = [witness]

    # 8. Validate
    print(f"P2WSH SCRIPTPUBKEY: {parser.parse_script(p2wsh_scriptpubkey.script)}")
    print(f"P2WSH REDEEM SCRIPT: {parser.parse_script(redeem_scriptpubkey.script)}")

    assert validator.validate_utxo(tx, 0), "P2WSH Failed assertion"


def test_p2wsh_p2pkh(test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    """
    Test P2WSH where the redeem script is a P2PKH.
    """
    script_engine.clear_stacks()
    test_db._clear_db()

    # 1. Generate keypair
    privkey, compressed_pubkey = generate_keypair()

    # 2. Create redeem script (P2PKH)
    redeem_scriptpubkey = pubkey_factory.p2pkh(compressed_pubkey)

    # 3. Create P2WSH scriptpubkey
    p2wsh_scriptpubkey = pubkey_factory.p2wsh(redeem_scriptpubkey.script)

    # 4. Create UTXO
    utxo = make_utxo(p2wsh_scriptpubkey.script)
    test_db.add_utxo(utxo)
    validator = ScriptValidator(test_db)

    # 5. Create transaction
    tx = build_tx(utxo, b'\x6a')
    tx.segwit = True

    # 6. Get segwit sighash (scriptCode = redeem script)
    segwit_sighash = sig_engine.get_segwit_sighash(tx, 0, redeem_scriptpubkey.script, utxo.amount, 1)
    segwit_sig = sig_engine.sign_message(privkey, segwit_sighash, 1)

    # 7. Build witness stack: [signature, pubkey, redeem_script]
    witness_items = [WitnessItem(segwit_sig), WitnessItem(compressed_pubkey), WitnessItem(redeem_scriptpubkey.script)]
    tx.witnesses = [Witness(witness_items)]

    # 8. Validate
    print(f"P2WSH(P2PKH) SCRIPTPUBKEY: {parser.parse_script(p2wsh_scriptpubkey.script)}")
    print(f"P2WSH(P2PKH) REDEEM SCRIPT: {parser.parse_script(redeem_scriptpubkey.script)}")
    assert validator.validate_utxo(tx, 0), "P2WSH(P2PKH) Failed assertion"


def test_p2wsh_p2ms(test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    """
    Test P2WSH where the redeem script is a 2-of-3 multisig.
    """
    script_engine.clear_stacks()
    test_db._clear_db()

    # 1. Generate 3 keypairs
    keys = [generate_keypair() for _ in range(3)]
    privkeys = [k[0] for k in keys]
    pubkeys = [k[1] for k in keys]

    # 2. Create redeem script (2-of-3 multisig)
    redeem_scriptpubkey = pubkey_factory.p2ms(pubkeys, signum=2)

    # 3. Create P2WSH scriptpubkey
    p2wsh_scriptpubkey = pubkey_factory.p2wsh(redeem_scriptpubkey.script)

    # 4. Create UTXO
    utxo = make_utxo(p2wsh_scriptpubkey.script)
    test_db.add_utxo(utxo)
    validator = ScriptValidator(test_db)

    # 5. Create transaction
    tx = build_tx(utxo, b'\x6a')
    tx.segwit = True

    # 6. Get segwit sighash
    segwit_sighash = sig_engine.get_segwit_sighash(tx, 0, redeem_scriptpubkey.script, utxo.amount, 1)
    sig1 = sig_engine.sign_message(privkeys[0], segwit_sighash, 1)
    sig2 = sig_engine.sign_message(privkeys[1], segwit_sighash, 1)

    # 7. Build witness: [dummy OP_0, sig1, sig2, redeem_script]
    witness_items = [WitnessItem(b''), WitnessItem(sig1), WitnessItem(sig2), WitnessItem(redeem_scriptpubkey.script)]
    tx.witnesses = [Witness(witness_items)]

    # 8. Validate
    print(f"P2WSH(P2MS) SCRIPTPUBKEY: {parser.parse_script(p2wsh_scriptpubkey.script)}")
    print(f"P2WSH(P2MS) REDEEM SCRIPT: {parser.parse_script(redeem_scriptpubkey.script)}")
    assert validator.validate_utxo(tx, 0), "P2WSH(P2MS) Failed assertion"


def test_p2tr_keypath(test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    """
    Taproot key path spending:
        - Generate internal key
        - Tweak it to get output key
        - Use output key in scriptPubKey
        - Sign with internal key (schnorr)
        - Add signature to witness
        - Validate
    """
    script_engine.clear_stacks()
    test_db._clear_db()
    taproot = Taproot()

    # 1. Generate keypair
    privkey, pubkey = generate_keypair()  # pubkey = compressed (33 bytes)
    xonly_pubkey = pubkey[1:]

    # 2. Tweak keypair
    tweak = taproot.tweak_data(xonly_pubkey)
    tweaked_pubkey = taproot.tweak_pubkey(xonly_pubkey)
    tweaked_privkey = taproot.tweak_privkey(privkey, tweak)

    # 3. Create UTXO and tx
    p2tr_scriptpubkey = pubkey_factory.p2tr(tweaked_pubkey)
    utxo = make_utxo(p2tr_scriptpubkey.script)
    test_db.add_utxo(utxo)

    tx = build_tx(utxo, b'\x6a')
    tx.segwit = True
    tx.inputs[0].txid = utxo.txid  # Link input to known UTXO

    # 4. Sign and build witness
    sighash = sig_engine.get_taproot_sighash(tx, 0, [utxo])
    schnorr_sig = sig_engine.schnorr_signature(int.from_bytes(tweaked_privkey, "big"), sighash)
    tx.witnesses = [Witness([WitnessItem(schnorr_sig)])]

    # Verify signature
    assert sig_engine.verify_schnorr_signature(int.from_bytes(tweaked_pubkey, "big"), sighash, schnorr_sig), \
        "Tweaked pubkey failed tweaked privkey Schnorr signature"

    # 5. Validate
    validator = ScriptValidator(test_db)
    print(f"P2TR SCRIPTPUBKEY: {parser.parse_script(p2tr_scriptpubkey.script)}")
    assert validator.validate_utxo(tx, 0), "P2TR keypath spend failed"


def test_p2tr_scriptpath_simple(test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    """
    Taproot script path spending:
        - Create internal key + leaf script (e.g., P2PK)
        - Compute TapLeaf hash
        - Tweak internal key using leaf hash
        - Build control block (version + internal key)
        - Create transaction, build sighash, and sign
        - Build witness: [sig, leaf_script, control_block]
        - Validate
    """
    script_engine.clear_stacks()
    test_db._clear_db()
    taproot = Taproot()

    # 1. Keypair and internal pubkey
    privkey, pubkey = generate_keypair()
    xonly_pubkey = pubkey[1:]  # drop prefix byte

    # 2. Leaf script: simple OP_3 OP_EQUAL
    leaf_script = b'\x53\x87'

    # 3. Create script tree
    script_tree = ScriptTree([leaf_script])
    merkle_root = script_tree.root

    # 4. Tweak
    tweak = taproot.tweak_data(xonly_pubkey + merkle_root)
    tweaked_pubkey = taproot.tweak_pubkey(xonly_pubkey, merkle_root)

    # 5. Create P2TR scriptPubKey and UTXO
    p2tr_scriptpubkey = pubkey_factory.p2tr(tweaked_pubkey)
    utxo = make_utxo(p2tr_scriptpubkey.script)
    test_db.add_utxo(utxo)
    validator = ScriptValidator(test_db)

    # 6. Create transaction
    tx = build_tx(utxo, b'\x6a')  # OP_RETURN output
    tx.segwit = True
    tx.inputs[0].txid = utxo.txid

    # 7. Construct script path spend
    unlock_script = b'\x03'  # script input | 0x03 gets pushed to stack
    control_byte = taproot.get_control_byte(xonly_pubkey)
    merkle_path = b''  # No merkle path when only 1 leaf
    control_block = control_byte + xonly_pubkey + merkle_path

    # 8 Create witness and add to tx
    scriptpath_witness = Witness(
        [WitnessItem(unlock_script), WitnessItem(leaf_script), WitnessItem(control_block)]
    )
    tx.witnesses = [scriptpath_witness]

    # 9. Validate
    print(f"P2TR(SCRIPT) SCRIPTPUBKEY: {parser.parse_script(p2tr_scriptpubkey.script)}")
    assert validator.validate_utxo(tx, 0), "P2TR scriptpath spend failed"


def test_p2tr_scriptpath_sig_example(test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    """
    From learnmeabitcoin.com
    """
    script_engine.clear_stacks()
    test_db._clear_db()
    taproot = Taproot()

    privkey = int.from_bytes(bytes.fromhex("9b8de5d7f20a8ebb026a82babac3aa47a008debbfde5348962b2c46520bd5189"), "big")
    xonly_pubkey = bytes.fromhex("6d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0")

    internal_pubkey = bytes.fromhex("924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329")

    tx = Transaction.from_bytes(
        bytes.fromhex(
            "020000000001013cfe8b95d22502698fd98837f83d8d4be31ee3eddd9d1ab1a95654c64604c4d10000000000ffffffff01983a0000000000001600140de745dc58d8e62e6f47bde30cd5804a82016f9e0000000000")
    )

    # 2. Leaf script:  OP_PUSHBYTES_32 6d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0 OP_CHECKSIG

    leaf_script = bytes.fromhex("206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac")
    script_tree = ScriptTree([leaf_script])
    merkle_root = script_tree.root

    # 3. Tweak public key
    tweak = taproot.tweak_data(internal_pubkey + merkle_root)
    tweaked_pubkey = taproot.tweak_pubkey(internal_pubkey, merkle_root)
    x_only_tweak = taproot.tweak_data(xonly_pubkey + merkle_root)
    tweaked_xonly_pubkey = taproot.tweak_pubkey(xonly_pubkey, merkle_root)
    tweaked_xonly_privkey = taproot.tweak_privkey(privkey, x_only_tweak)

    # 4. ScriptPubKey and utxo
    p2tr_scriptpubkey = pubkey_factory.p2tr(tweaked_pubkey)
    utxo = make_utxo(p2tr_scriptpubkey.script, amount=20000, txid=tx.inputs[0].txid)
    test_db.add_utxo(utxo)

    # 5. Control block
    control_byte = taproot.get_control_byte(tweaked_pubkey)
    control_block = control_byte + internal_pubkey

    # 7. Calculate extension
    leaf_hash = taproot.get_leaf_hash(leaf_script)

    extension = leaf_hash + b'\x00' + bytes.fromhex("ffffffff")

    print(f"TX BEFORE GETTING TEST SIGHASH: {tx.to_json()}")

    # 8. Signature
    sighash = sig_engine.get_taproot_sighash(tx, 0, [utxo], extension, hash_type=SigHash.ALL)
    taproot_sig = sig_engine.schnorr_signature(privkey, sighash)
    assert sig_engine.verify_schnorr_signature(int.from_bytes(xonly_pubkey, "big"), sighash, taproot_sig), \
        "Tweaked pubkey failed schnorr signature"

    # Verify Tweaks
    verify_sig = sig_engine.schnorr_signature(int.from_bytes(tweaked_xonly_privkey, "big"), sighash)
    assert sig_engine.verify_schnorr_signature(int.from_bytes(tweaked_xonly_pubkey, "big"), sighash, verify_sig)

    # Add sighash byte to signature
    taproot_sig += SigHash.ALL.to_byte()

    # 9. Create witness
    witness = Witness(
        [WitnessItem(taproot_sig), WitnessItem(leaf_script), WitnessItem(control_block)]
    )
    tx.witnesses = [witness]

    # # -- TESTING
    # print("\n" + ("---" * 80))
    # print(f"P2TR(SCRIPT) SCRIPTPUBKEY: {parser.parse_script(p2tr_scriptpubkey.script)}")
    # print(f"LEAF SCRIPT: {parser.parse_script(leaf_script)}")
    # print(f"XONLY PUBKEY: {xonly_pubkey.hex()}")
    # print(f"TWEAK: {tweak.hex()}")
    # print(f"TWEAKED PUBKEY: {tweaked_pubkey.hex()}")
    # print(f"MERKLE ROOT: {merkle_root.hex()}")
    # print(f"PRIVATE KEY: {privkey.to_bytes(32, 'big').hex()}")
    # print(f"LEAF HASH: {leaf_hash.hex()}")
    # print(f"LEAF DATA: {taproot.get_leaf(leaf_script).hex()}")
    # print(f"CONTROL BLOCK: {control_block.hex()}")
    # print(f"SIGHASH: {sighash.hex()}")
    # print(f"SIGNATURE: {taproot_sig.hex()}")
    # print(f"EXTENSION: {extension.hex()}")
    # print(f"---" * 80)

    # 10. Modify tx to grab the created utxo
    tx.inputs[0].txid = utxo.txid
    tx.segwit = True

    # 11. Validate
    validator = ScriptValidator(test_db)
    print(f"P2TR(SCRIPT) SCRIPTPUBKEY: {parser.parse_script(p2tr_scriptpubkey.script)}")
    assert validator.validate_utxo(tx, 0), "P2TR scriptpath spend failed"


def test_p2tr_scriptpath_sig(test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    """
    Taproot script path spending:
        - Create internal key + leaf script (e.g., P2PK)
        - Compute TapLeaf hash
        - Tweak internal key using leaf hash
        - Build control block (version + internal key)
        - Create transaction, build sighash, and sign
        - Build witness: [sig, leaf_script, control_block]
        - Validate
    """
    script_engine.clear_stacks()
    test_db._clear_db()
    taproot = Taproot()

    # 1. Get key path keypair and leaf script keypair
    path_privkey, path_pubkey = generate_keypair(xonly=True)  # This pubkey will be for key path spend
    leaf_privkey, leaf_pubkey = generate_keypair(xonly=True)  # These pubkeys will be used for leaf script

    # 2. Create leaft script
    leaf_script = b'\x20' + leaf_pubkey + b'\xac'
    script_tree = ScriptTree([leaf_script])
    merkle_root = script_tree.root

    # 3. Tweak pubkey, create scriptpubkey and utxo
    tweaked_pubkey = taproot.tweak_pubkey(path_pubkey, merkle_root)
    tweaked_privkey = taproot.tweak_privkey(path_privkey, taproot.tweak_data(path_pubkey + merkle_root))
    p2tr_scriptpubkey = pubkey_factory.p2tr(tweaked_pubkey)
    utxo = make_utxo(p2tr_scriptpubkey.script)
    test_db.add_utxo(utxo)

    # 4. Create tx and control block
    tx = build_tx(utxo, b'\x6a', segwit=True)
    control_byte = taproot.get_control_byte(tweaked_pubkey)
    control_block = control_byte + path_pubkey

    # 5. Calculate extension
    leaf_hash = taproot.get_leaf_hash(leaf_script)
    extension = leaf_hash + b'\x00' + bytes.fromhex("ffffffff")

    # 6. Signature and verification of keys
    sighash = sig_engine.get_taproot_sighash(tx, 0, [utxo], extension, hash_type=SigHash.ALL)
    taproot_sig = sig_engine.schnorr_signature(leaf_privkey, sighash)
    assert sig_engine.verify_schnorr_signature(int.from_bytes(leaf_pubkey, "big"), sighash, taproot_sig)

    # Verify Tweaks
    verify_sig = sig_engine.schnorr_signature(int.from_bytes(tweaked_privkey, "big"), sighash)
    assert sig_engine.verify_schnorr_signature(int.from_bytes(tweaked_pubkey, "big"), sighash, verify_sig)

    # Add sighash byte to signature
    taproot_sig += SigHash.ALL.to_byte()

    # 9. Create witness
    witness = Witness(
        [WitnessItem(taproot_sig), WitnessItem(leaf_script), WitnessItem(control_block)]
    )
    tx.witnesses = [witness]

    # 10. Validate
    validator = ScriptValidator(test_db)
    print(f"P2TR(SCRIPT) SCRIPTPUBKEY: {parser.parse_script(p2tr_scriptpubkey.script)}")
    assert validator.validate_utxo(tx, 0), "P2TR scriptpath spend failed"


def test_p2tr_scriptpath_tree_example(test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    """
    Taproot script path spending:
        - Create internal key + leaf script (e.g., P2PK)
        - Compute TapLeaf hash
        - Tweak internal key using leaf hash
        - Build control block (version + internal key)
        - Create transaction, build sighash, and sign
        - Build witness: [sig, leaf_script, control_block]
        - Validate
    """
    script_engine.clear_stacks()
    test_db._clear_db()
    taproot = Taproot()

    # 1. Get public key
    internal_pubkey = bytes.fromhex("924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329")

    # 2. Get leaf data
    leaf1_script = bytes.fromhex("5187")
    leaf1_hash = taproot.get_leaf_hash(leaf1_script)

    leaf2_script = bytes.fromhex("5287")
    leaf2_hash = taproot.get_leaf_hash(leaf2_script)

    leaf3_script = bytes.fromhex("5387")
    leaf3_hash = taproot.get_leaf_hash(leaf3_script)

    leaf4_script = bytes.fromhex("5487")
    leaf4_hash = taproot.get_leaf_hash(leaf4_script)

    leaf5_script = bytes.fromhex("5587")
    leaf5_hash = taproot.get_leaf_hash(leaf5_script)

    # 3. Create script tree
    script_tree = ScriptTree([leaf1_script, leaf2_script, leaf3_script, leaf4_script, leaf5_script], balanced=False)
    merkle_root = script_tree.root

    # 4. Tweak pubkey
    tweak = taproot.tweak_data(internal_pubkey + merkle_root)
    tweaked_pubkey = taproot.tweak_pubkey(internal_pubkey, merkle_root)

    # 5. Get scriptpubkey
    p2tr_scriptpubkey = pubkey_factory.p2tr(tweaked_pubkey)
    utxo = make_utxo(p2tr_scriptpubkey.script)
    test_db.add_utxo(utxo)

    # 6. Spend leaf # 3
    script_inputs = bytes.fromhex("03")
    script = leaf3_script
    spend_script = bytes.fromhex("5387")
    control_byte = bytes.fromhex("c0")

    # 7. Get merkle path
    branch_1 = taproot.tap_branch(leaf1_hash, leaf2_hash)
    merkle_path = branch_1 + leaf4_hash + leaf5_hash

    # 8. Get control block
    control_block = control_byte + internal_pubkey + merkle_path

    # 9. Construct tx
    tx = Transaction.from_bytes(bytes.fromhex(
        "02000000000101d7c0aa93d852c70ed440c5295242c2ac06f41c3a2a174b5a5b112cebdf0f7bec0000000000ffffffff014c1d0000000000001600140de745dc58d8e62e6f47bde30cd5804a82016f9e0000000000"))
    tx.segwit = True
    tx.inputs[0].txid = utxo.txid

    # 10. Create witness
    witness = Witness([
        WitnessItem(script_inputs), WitnessItem(script), WitnessItem(control_block)
    ])
    tx.witnesses = [witness]

    # --- TESTING
    print("===" * 50)
    print(f"MERKLE ROOT: {merkle_root.hex()}")
    print(f"TWEAK: {tweak.hex()}")
    print(f"TWEAKED PUBKEY: {tweaked_pubkey.hex()}")
    print(f"SCRIPTPUBKEY: {p2tr_scriptpubkey.script.hex()}")
    print(f"TX: {tx.to_json()}")
    print("===" * 50)

    # 9. Validate
    print(f"P2TR(SCRIPT) SCRIPTPUBKEY: {parser.parse_script(p2tr_scriptpubkey.script)}")
    validator = ScriptValidator(test_db)
    assert validator.validate_utxo(tx, 0), "P2TR scriptpath spend failed"


def test_p2tr_scriptpath_tree(test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    """
    We test spending the 3rd leaf in an unbalanced tree (aka: linear).

    # ┌────────┐ ┌────────┐
    # │ leaf 1 │ │ leaf 2 │
    # └───┬────┘ └───┬────┘
    #     └────┬─────┘
    #      X───┴────┐ ┌────────┐
    #      │branch 1│ │ leaf 3 │ <- spending
    #      └───┬────┘ └─────┬──┘
    #          └─────┬──────┘
    #            ┌───┴────┐ X────────┐
    #            │branch 2│ │ leaf 4 │
    #            └───┬────┘ └────┬───┘
    #                └────┬──────┘
    #                 ┌───┴────┐ X────────┐
    #                 │branch 3│ │ leaf 5 │
    #                 └───┬────┘ └────┬───┘
    #                     └─────┬─────┘
    #                       ┌───┴────┐
    #                       │branch 4│
    #                       └────────┘

    """
    script_engine.clear_stacks()
    test_db._clear_db()
    taproot = Taproot()

    # 1. Internal key and 5 leaf keys
    internal_privkey, internal_pubkey = generate_keypair(xonly=True)  # Keypair for the Script Path
    leaf_keys = [generate_keypair(xonly=True) for _ in range(5)]  # Keys for the leaves of the tree

    # 2. Leaf scripts = OP_PUSHBYTES_32 <xonly_pubkey> OP_CHECKSIG
    leaf_scripts = [b'\x20' + pubkey + b'\xac' for (_, pubkey) in leaf_keys]

    # 3. Build a linear script tree and get its root
    script_tree = ScriptTree(leaf_scripts, balanced=False)
    merkle_root = script_tree.root
    leaf_hashes = script_tree.leaves

    # 4. Tweak internal pubkey with merkle root
    tweak = taproot.tweak_data(internal_pubkey + merkle_root)
    tweaked_pubkey = taproot.tweak_pubkey(internal_pubkey, merkle_root)

    # 5. Create P2TR output and UTXO
    p2tr_scriptpubkey = pubkey_factory.p2tr(tweaked_pubkey)
    utxo = make_utxo(p2tr_scriptpubkey.script)
    test_db.add_utxo(utxo)
    validator = ScriptValidator(test_db)

    # 6. Build segwit transaction spending that UTXO
    tx = build_tx(utxo, b'\x6a', segwit=True)
    tx.inputs[0].txid = utxo.txid

    # 7. Compute merkle path for the third leaf (index 2)
    #    In a linear tree: path = H(leaf0,leaf1) || leaf4 || leaf5
    branch = Branch(leaf_hashes[0], leaf_hashes[1])
    merkle_path = branch.branch_hash + leaf_hashes[3].leaf_hash + leaf_hashes[4].leaf_hash
    assert taproot.eval_merkle_path(leaf_hashes[2].leaf_hash, merkle_path) == merkle_root, "Merkle path failed"

    # 8. Build control block: [control_byte||internal_key||merkle_path]
    control_byte = taproot.get_control_byte(tweaked_pubkey)
    control_block = control_byte + internal_pubkey + merkle_path

    # 9. Calculate extension for 3rd leaf (index 2)
    leaf_hash = leaf_hashes[2].leaf_hash
    extension = leaf_hash + b'\x00' + bytes.fromhex("ffffffff")

    # 10. Use private key from leaf for signature
    sighash = sig_engine.get_taproot_sighash(tx, 0, [utxo], extension, hash_type=SigHash.ALL)
    taproot_sig = sig_engine.schnorr_signature(leaf_keys[2][0], sighash)
    assert sig_engine.verify_schnorr_signature(int.from_bytes(leaf_keys[2][1], "big"), sighash, taproot_sig), \
        "Failed to verify schnorr signature for leaf keys"

    # 11. Add sighash byte to signature
    taproot_sig += SigHash.ALL.to_byte()

    # 12. Create witness and add to tx
    witness = Witness([WitnessItem(taproot_sig), WitnessItem(leaf_scripts[2]), WitnessItem(control_block)])
    tx.witnesses = [witness]

    print("===" * 50)
    print(f"MERKLE ROOT: {merkle_root.hex()}")
    print(f"TWEAK: {tweak.hex()}")
    print(f"TWEAKED PUBKEY: {tweaked_pubkey.hex()}")
    print(f"SCRIPTPUBKEY: {p2tr_scriptpubkey.script.hex()}")
    print(f"TX: {tx.to_json()}")
    print(f"INTERNAL PUBKEY: {internal_pubkey.hex()}")
    print("===" * 50)

    # 13. Validate
    print(f"P2TR(SCRIPT) SCRIPTPUBKEY: {parser.parse_script(p2tr_scriptpubkey.script)}")
    assert validator.validate_utxo(tx, 0), "P2TR scriptpath spend failed"
