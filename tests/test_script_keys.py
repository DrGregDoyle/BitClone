"""
Tests for verifying that various script_sig + script_pub_keys will evaluate to True in the script engine
"""

from random import randint
from secrets import randbits

from src.data import compress_public_key, write_compact_size, decode_der_signature, encode_der_signature
from src.logger import get_logger
from src.script import ScriptValidator
from src.tx import UTXO, Transaction, Input, Output

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


def add_scriptsig(tx: Transaction, script_sig: bytes, input_index: int = 0) -> Transaction:
    tx.inputs[input_index].script_sig = script_sig
    tx.inputs[input_index].script_sig_size = write_compact_size(len(script_sig))
    return tx


# -- TESTS
def test_p2pk(curve, test_db, script_engine, tx_engine, scriptsig_engine, pubkey_engine, parser):
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
    p2pk_scriptpubkey = pubkey_engine.p2pk(pubkey=compressed_pubkey).scriptpubkey

    # 3. Create UTXO with that scriptPubKey
    p2pk_utxo = make_utxo(p2pk_scriptpubkey)
    test_db.add_utxo(p2pk_utxo)
    validator = ScriptValidator(test_db)

    # 4. Create transaction and sign it
    p2pk_tx = build_tx(p2pk_utxo, b'\x6a')  # OP_RETURN output
    p2pk_signature = tx_engine.get_legacy_sig(private_key, p2pk_tx)

    # 5. Build scriptSig and attach to tx
    p2pk_scriptsig = scriptsig_engine.p2pk(p2pk_signature)
    final_tx = add_scriptsig(p2pk_tx, p2pk_scriptsig)

    # 6. Modify input to reference utxo in db
    final_tx.inputs[0].txid = bytes.fromhex("f" * 64)

    # 7. Validate
    final_script = p2pk_scriptsig + p2pk_scriptpubkey
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
    bad_scriptsig = scriptsig_engine.p2pk(bad_sig)
    bad_tx = add_scriptsig(p2pk_tx, bad_scriptsig)
    bad_script = bad_scriptsig + p2pk_scriptpubkey
    assert not script_engine.eval_script(bad_script, bad_tx, utxo=p2pk_utxo,
                                         input_index=0), "p2pk tampered signature passed"


def test_p2pkh(curve, test_db, script_engine, tx_engine, scriptsig_engine, pubkey_engine, parser):
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
    p2pkh_scriptpubkey = pubkey_engine.p2pkh(compressed_pubkey).scriptpubkey

    # 4. Create UTXO with that pubkey
    p2pkh_utxo = make_utxo(p2pkh_scriptpubkey)
    test_db.add_utxo(p2pkh_utxo)
    validator = ScriptValidator(test_db)

    # 5. Create tx with that utxo and sign it
    p2pkh_tx = build_tx(p2pkh_utxo, b'\x6a')  # OP_RETURN
    p2pkh_signature = tx_engine.get_legacy_sig(private_key, p2pkh_tx)

    # 6. Build scriptsig and put it in the input
    p2pkh_scriptsig = scriptsig_engine.p2pkh(p2pkh_signature, compressed_pubkey)
    final_tx = add_scriptsig(p2pkh_tx, p2pkh_scriptsig)

    # 7. Modify input to reference utxo in db
    final_tx.inputs[0].txid = bytes.fromhex("f" * 64)

    # 8. Validate
    final_script = p2pkh_scriptsig + p2pkh_scriptpubkey
    asm = parser.parse_script(final_script)
    print(f"P2PKH ASM: {asm}")
    assert validator.validate_utxo(final_tx, 0), "p2pkh scriptSig + scriptpubkey failed"
    assert script_engine.eval_script(final_script, final_tx, utxo=p2pkh_utxo, input_index=0), "p2pkh scriptSig + " \
                                                                                              "scriptpubkey failed"


def test_p2ms(curve, test_db, script_engine, tx_engine, scriptsig_engine, pubkey_engine, parser):
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
    multisig_result = pubkey_engine.p2ms(pubkeys, signum=2)
    p2ms_scriptpubkey = multisig_result.scriptpubkey

    # 3. Create UTXO and tx
    multisig_utxo = make_utxo(p2ms_scriptpubkey)
    test_db.add_utxo(multisig_utxo)
    multisig_tx = build_tx(multisig_utxo, b'\x6a')
    validator = ScriptValidator(test_db)

    # 4. Sign with first two keys
    sig1 = tx_engine.get_legacy_sig(privkeys[0], multisig_tx)
    sig2 = tx_engine.get_legacy_sig(privkeys[1], multisig_tx)

    # 5. Build scriptSig: OP_0 <sig1> <sig2>
    multisig_scriptsig = scriptsig_engine.p2ms([sig1, sig2])
    final_tx = add_scriptsig(multisig_tx, multisig_scriptsig)

    # 6. Modify input to reference utxo in db
    final_tx.inputs[0].txid = bytes.fromhex("f" * 64)

    # 7. Validate
    final_script = multisig_scriptsig + p2ms_scriptpubkey
    asm = parser.parse_script(final_script)
    logger.debug(f"P2MS ASM: {asm}")
    assert validator.validate_utxo(final_tx, 0), "p2ms 2-of-3 failed"


def test_p2sh_p2pk(curve, test_db, script_engine, tx_engine, scriptsig_engine, pubkey_engine, parser):
    script_engine.clear_stacks()
    test_db._clear_db()
    # 1. Generate key
    privkey, pubkey = generate_keypair(curve)

    # 2. Create redeem script
    redeem_script = pubkey_engine.p2pk(pubkey).scriptpubkey
    p2sh_scriptpubkey = pubkey_engine.p2sh(redeem_script).scriptpubkey

    # 3. Create UTXO
    utxo = make_utxo(p2sh_scriptpubkey)
    test_db.add_utxo(utxo)
    validator = ScriptValidator(test_db)

    # 4. Create tx and sign
    tx = build_tx(utxo, b'\x6a')
    sig = tx_engine.get_legacy_sig(privkey, tx)

    # 5. Build scriptsig
    scriptsig = scriptsig_engine.p2sh([sig], redeem_script)
    final_tx = add_scriptsig(tx, scriptsig)

    # 6. Modify input to reference utxo in db
    final_tx.inputs[0].txid = bytes.fromhex("f" * 64)

    # 7. Validate
    full_script = scriptsig + p2sh_scriptpubkey
    asm = parser.parse_script(full_script)
    print(f"P2SH(P2PK) ASM: {asm}")
    assert validator.validate_utxo(final_tx, 0), "P2SH(P2PK) failed"


def test_p2sh_p2pkh(curve, test_db, script_engine, tx_engine, scriptsig_engine, pubkey_engine, parser):
    script_engine.clear_stacks()
    test_db._clear_db()
    # 1. Generate key
    privkey, pubkey = generate_keypair(curve)

    # 2. Create redeem script
    redeem_script = pubkey_engine.p2pkh(pubkey).scriptpubkey
    p2sh_scriptpubkey = pubkey_engine.p2sh(redeem_script).scriptpubkey

    # 3. Create UTXO
    utxo = make_utxo(p2sh_scriptpubkey)
    test_db.add_utxo(utxo)
    validator = ScriptValidator(test_db)

    # 4. Create tx and sign
    tx = build_tx(utxo, b'\x6a')
    sig = tx_engine.get_legacy_sig(privkey, tx)

    # 5. Build scriptsig
    scriptsig = scriptsig_engine.p2sh([sig, pubkey], redeem_script)
    final_tx = add_scriptsig(tx, scriptsig)

    # 6. Modify input to reference utxo in db
    final_tx.inputs[0].txid = bytes.fromhex("f" * 64)

    # 7. Validate
    full_script = scriptsig + p2sh_scriptpubkey
    asm = parser.parse_script(full_script)
    print(f"P2SH(P2PKH) ASM: {asm}")
    assert validator.validate_utxo(final_tx, 0), "P2SH(P2PK) failed"


def test_p2sh_p2ms(curve, test_db, script_engine, tx_engine, scriptsig_engine, pubkey_engine, parser):
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
    multisig_result = pubkey_engine.p2ms(pubkeys, signum=2)
    redeem_script = multisig_result.scriptpubkey
    p2sh_scriptpubkey = pubkey_engine.p2sh(redeem_script).scriptpubkey

    # 3. Create UTXO
    utxo = make_utxo(p2sh_scriptpubkey)
    test_db.add_utxo(utxo)
    validator = ScriptValidator(test_db)

    # 4. Build tx
    tx = build_tx(utxo, b'\x6a')

    # 5. Get signatures for 2 keys
    sig1 = tx_engine.get_legacy_sig(privkeys[0], tx)
    sig2 = tx_engine.get_legacy_sig(privkeys[1], tx)

    # 6. Build scriptSig: OP_0 <sig1> <sig2> <redeem_script>
    scriptsig = scriptsig_engine.p2sh([b'\x00', sig1, sig2], redeem_script)
    final_tx = add_scriptsig(tx, scriptsig)

    # 7. Modify input to reference utxo in db
    final_tx.inputs[0].txid = bytes.fromhex("f" * 64)

    # 8. Validate
    full_script = scriptsig + p2sh_scriptpubkey
    asm = parser.parse_script(full_script)
    print(f"P2SH(P2MS) ASM: {asm}")
    assert validator.validate_utxo(final_tx, 0), "P2SH(P2MS) failed"


def test_p2wpkh(curve, test_db, script_engine, tx_engine, scriptsig_engine, pubkey_engine, parser):
    """
    Tests P2WPKH
    """
    script_engine.clear_stacks()
    test_db._clear_db()
    # 1. Generate keypair
    privkey, compressed_pubkey = generate_keypair(curve)

    # 2. Get P2WPKH scriptpubkey
    p2wpkh_scriptpubkey = pubkey_engine.p2wpkh(compressed_pubkey).scriptpubkey

    # 3. Create UTXO
    utxo = make_utxo(p2wpkh_scriptpubkey)
    test_db.add_utxo(utxo)
    validator = ScriptValidator(test_db)

    # 4. Create a tx
    tx = build_tx(utxo, b'\x6a')
    tx.segwit = True

    # 5. Get witness inserted into tx
    final_tx = tx_engine.get_segwit_sig(privkey, tx, utxo.amount, 0)
    witness = final_tx.witnesses[0]

    # # 6. Modify input to reference utxo in db
    # final_tx.inputs[0].txid = bytes.fromhex("f" * 64)

    # 7. Validate
    print(f"P2WPKH SCRIPTPUBKEY: {parser.parse_script(p2wpkh_scriptpubkey)}")
    assert validator.validate_utxo(final_tx, 0), "P2WPKH Failed assertion"
