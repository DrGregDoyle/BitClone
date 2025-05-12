"""
Tests for verifying that various script_sig + script_pub_keys will evaluate to True in the script engine
"""

from random import randint
from secrets import randbits

from src.crypto import hash160, Taproot
from src.data import compress_public_key, write_compact_size, decode_der_signature, encode_der_signature
from src.logger import get_logger
from src.script import ScriptValidator
from src.tx import UTXO, Transaction, Input, Output, Witness, WitnessItem

logger = get_logger(__name__)


# -- HELPERS
def mutate_signature(signature: bytes, mode: str = "s", curve_order: int = None) -> bytes:
    """
    Safely mutates a Bitcoin ECDSA signature (DER + sighash byte) for failure testing.

    Args:
        signature (bytes): Original signature (DER-encoded + sighash byte)
        mode (str): What to mutate:
            - "sighash": flips one bit in sighash byte
            - "s": modifies s slightly
            - "r": modifies r slightly
        curve_order (int): Needed for modular operations on r/s

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

    if curve_order is None:
        raise ValueError("curve_order required for r/s mutation")

    r, s = decode_der_signature(der_sig)

    if mode == "r":
        r = (r + randint(1, 5)) % curve_order or 1
    elif mode == "s":
        s = (s + randint(1, 5)) % curve_order or 1
    else:
        raise ValueError(f"Unknown mode: {mode}")

    new_der = encode_der_signature(r, s)
    return new_der + bytes([sighash_byte])


def generate_keypair(curve):
    private_key = 0
    while not (1 <= private_key < curve.order):
        private_key = randbits(256)
    pubkey_point = curve.multiply_generator(private_key)
    compressed_pubkey = compress_public_key(pubkey_point)
    return private_key, compressed_pubkey


def make_utxo(pubkey_script: bytes, amount=50000):
    return UTXO(
        txid=bytes.fromhex("f" * 64),
        vout=0,
        amount=amount,
        script_pubkey=pubkey_script
    )


def build_tx(utxo: UTXO, output_script: bytes):
    return Transaction(
        inputs=[Input(utxo.txid, utxo.vout, b'', sequence=0xffffffff)],
        outputs=[Output(49000, output_script)],
        segwit=False
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
def test_p2pk(curve, test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
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
    private_key, compressed_pubkey = generate_keypair(curve)

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
    bad_sig = mutate_signature(p2pk_signature, mode="s", curve_order=curve.order)
    bad_scriptsig = scriptsig_factory.p2pk(bad_sig)
    bad_tx = add_scriptsig(p2pk_tx, bad_scriptsig.script)
    bad_script = bad_scriptsig.script + p2pk_scriptpubkey.script
    assert not script_engine.eval_script(bad_script, bad_tx, utxo=p2pk_utxo,
                                         input_index=0), "p2pk tampered signature passed"


def test_p2pkh(curve, test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
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
    private_key, compressed_pubkey = generate_keypair(curve)

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


def test_p2ms(curve, test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
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
    keys = [generate_keypair(curve) for _ in range(3)]
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


def test_p2sh_p2pk(curve, test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    script_engine.clear_stacks()
    test_db._clear_db()
    # 1. Generate key
    privkey, pubkey = generate_keypair(curve)

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


def test_p2sh_p2pkh(curve, test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    script_engine.clear_stacks()
    test_db._clear_db()
    # 1. Generate key
    privkey, pubkey = generate_keypair(curve)

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


def test_p2sh_p2ms(curve, test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
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
    keys = [generate_keypair(curve) for _ in range(3)]
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


def test_p2wpkh(curve, test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    """
    Tests P2WPKH
    """
    script_engine.clear_stacks()
    test_db._clear_db()
    # 1. Generate keypair
    privkey, compressed_pubkey = generate_keypair(curve)

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


def test_p2wsh_p2pk(curve, test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
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
    privkey, compressed_pubkey = generate_keypair(curve)

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


def test_p2wsh_p2pkh(curve, test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    """
    Test P2WSH where the redeem script is a P2PKH.
    """
    script_engine.clear_stacks()
    test_db._clear_db()

    # 1. Generate keypair
    privkey, compressed_pubkey = generate_keypair(curve)

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


def test_p2wsh_p2ms(curve, test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
    """
    Test P2WSH where the redeem script is a 2-of-3 multisig.
    """
    script_engine.clear_stacks()
    test_db._clear_db()

    # 1. Generate 3 keypairs
    keys = [generate_keypair(curve) for _ in range(3)]
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


def test_p2tr_keypath(curve, test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
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
    privkey, pubkey = generate_keypair(curve)  # pubkey = compressed (33 bytes)

    # 2. Tweak
    print(f"PRIVKEY: {privkey}")
    print(f"PUBKEY: {pubkey.hex()}")
    print(f"X-ONLY PUBKEY: {pubkey[1:].hex()}")
    tweaked_pubkey = taproot.tweak_pubkey(pubkey[1:])  # x-only pubkey, no merkle root
    tweak = taproot.taptweak(pubkey[1:])
    tweaked_privkey = taproot.tweak_privkey(privkey, tweak)
    tweaked_privkey_int = int.from_bytes(tweaked_privkey, "big")
    # tweaked_pubkey = pubkey[1:]   # Using pubkey itself passes validation

    # 3. Create P2TR scriptPubKey
    p2tr_scriptpubkey = pubkey_factory.p2tr(tweaked_pubkey)
    print(f"P2TR SCRIPTPUBKEY: {p2tr_scriptpubkey.to_json()}")
    utxo = make_utxo(p2tr_scriptpubkey.script)
    test_db.add_utxo(utxo)
    validator = ScriptValidator(test_db)

    # 4. Create tx and sign (keypath spend)
    tx = build_tx(utxo, b'\x6a')
    tx.segwit = True
    sighash = sig_engine.get_taproot_sighash(tx, 0, [utxo])
    schnorr_sig = sig_engine.schnorr_signature(tweaked_privkey_int, sighash, b'')
    print(f"SIGHASH: {sighash.hex()}")
    print(f"SCHNORR SIG: {schnorr_sig.hex()}")

    # 6. Add witness
    tx.witnesses = [Witness([WitnessItem(schnorr_sig)])]

    # 7. Validate
    print(f"P2TR SCRIPTPUBKEY: {parser.parse_script(p2tr_scriptpubkey.script)}")
    assert validator.validate_utxo(tx, 0), "P2TR keypath spend failed"

# def test_p2tr_scriptpath(curve, test_db, script_engine, sig_engine, scriptsig_factory, pubkey_factory, parser):
#     """
#     Taproot script path spending:
#         - Create leaf script (e.g. P2PK)
#         - Construct TapLeaf and tweak internal key
#         - Generate control block
#         - Build witness: [sig, leaf_script, control_block]
#         - Validate
#     """
#     script_engine.clear_stacks()
#     test_db._clear_db()
#
#     # 1. Keypair and pubkey
#     privkey, pubkey = generate_keypair(curve)
#     xonly_pubkey = pubkey[1:]
#
#     # 2. Leaf script (P2PK style)
#     leaf_script = b'\x21' + pubkey + b'\xac'  # PUSH33 <pubkey> CHECKSIG
#
#     # 3. Leaf hash (TapLeaf version 0xC0 || compact_size(script) || script)
#     leaf_version = b'\xc0'
#     leaf_hash = sig_engine.tagged_hash("TapLeaf", leaf_version + write_compact_size(len(leaf_script)) + leaf_script)
#
#     # 4. Tweak internal key
#     tweak = sig_engine.tagged_hash("TapTweak", xonly_pubkey + leaf_hash)
#     tweaked_pubkey = curve.xonly_tweak_add(xonly_pubkey, tweak)
#
#     # 5. Create scriptPubKey
#     p2tr_scriptpubkey = pubkey_factory.p2tr(tweaked_pubkey)
#     utxo = make_utxo(p2tr_scriptpubkey.script)
#     test_db.add_utxo(utxo)
#     validator = ScriptValidator(test_db)
#
#     # 6. Create tx and sighash
#     tx = build_tx(utxo, b'\x6a')
#     tx.segwit = True
#     sighash = sig_engine.get_taproot_scriptpath_sighash(tx, 0, utxo.amount, leaf_script, leaf_version)
#     schnorr_sig = sig_engine.sign_schnorr(privkey, sighash)
#
#     # 7. Control block (1 byte version + xonly internal key)
#     control_block = b'\xc0' + xonly_pubkey
#
#     # 8. Build witness
#     witness_items = [WitnessItem(schnorr_sig), WitnessItem(leaf_script), WitnessItem(control_block)]
#     tx.witnesses = [Witness(witness_items)]
#
#     # 9. Validate
#     print(f"P2TR(SCRIPT) SCRIPTPUBKEY: {parser.parse_script(p2tr_scriptpubkey.script)}")
#     assert validator.validate_utxo(tx, 0), "P2TR scriptpath spend failed"
