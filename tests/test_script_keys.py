"""
Tests for verifying that various script_sig + script_pub_keys will evaluate to True in the script engine
"""

from random import randint
from secrets import randbits

from src.crypto import hash160
from src.data import compress_public_key, write_compact_size, decode_der_signature, encode_der_signature
from src.tx import UTXO, Transaction, Input, Output


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


def test_p2pk(script_engine, tx_engine, curve, pubkey_engine, test_db, scriptsig_engine, parser):
    """
    Minimal Flow for a P2PK Test:
        -Generate keypair
        -Derive P2PK scriptPubKey.
        -Create a mock UTXO with that scriptPubKey.
        -Create a tx spending that UTXO and sign it.
        -Feed it to the ScriptEngine for validation.
    """
    # 1. Generate keypair
    private_key, compressed_pubkey = generate_keypair(curve)

    # 2. Get p2pk scriptPubkey
    p2pk_scriptpubkey = pubkey_engine.p2pk(pubkey=compressed_pubkey).scriptpubkey

    # 3. Create mock UTXO with given scriptpubkey
    test_utxo = make_utxo(p2pk_scriptpubkey)
    test_db.add_utxo(test_utxo)

    # 4. Create TX spending that UTXO and sign it
    test_input = Input(test_utxo.txid, test_utxo.vout, script_sig=b'', sequence=0xffffffff)
    test_output = Output(49000, b'\x6a')  # ScriptSig = OP_RETURN
    test_tx = Transaction(inputs=[test_input], outputs=[test_output], segwit=False)
    signature = tx_engine.get_legacy_sig(private_key, test_tx)
    p2pk_scriptsig = scriptsig_engine.p2pk(signature)
    test_tx.inputs[0].script_sig = p2pk_scriptsig
    test_tx.inputs[0].script_sig_size = write_compact_size(len(p2pk_scriptsig))

    # 5. Validate scriptsig + scriptpubkey in the engine
    final_script = p2pk_scriptsig + p2pk_scriptpubkey
    assert script_engine.eval_script(final_script, test_tx, input_index=0), "p2pk scriptSig + scriptpubkey failed " \
                                                                            "validation"

    # Logging
    print(f"P2PK SCRIPT HEX: {final_script.hex()}")
    print(f"P2PK ASM: {parser.parse_script(final_script)}")

    # 6. Check tampered signature case
    bad_sig = mutate_signature(signature, "s", curve_order=curve.order)
    bad_scriptsig = scriptsig_engine.p2pk(bytes(bad_sig))
    bad_script = bad_scriptsig + p2pk_scriptpubkey
    assert not script_engine.eval_script(bad_script, test_tx, input_index=0), "p2pk tampered scriptsig passed " \
                                                                              "validation"


def test_p2pkh(script_engine, tx_engine, curve, pubkey_engine, test_db, scriptsig_engine, parser):
    """
    Minimal flow for p2pkh test:
        -Generate pubkey
        -Compute hash160(pubkey)
        -Build P2PKH scriptPubKey
        -Create UTXO with that scriptPubKey
        -Create tx with that utxo and sign it
        -Build scriptSig: push signature, then pubkey
        -Assert full script evaluates to True
    """
    # 1. Generate keypair
    private_key, compressed_pubkey = generate_keypair(curve)

    # 2. Get hashpubkey
    hashpubkey = hash160(compressed_pubkey)

    # 3. Get p2pkh scriptpubkey
    p2pkh_scriptpubkey = pubkey_engine.p2pkh(compressed_pubkey).scriptpubkey

    # 4. Create UTXO with that pubkey
    p2pkh_utxo = make_utxo(p2pkh_scriptpubkey)
    test_db.add_utxo(p2pkh_utxo)

    # 5. Create tx with that utxo and sign it
    p2pkh_tx = build_tx(p2pkh_utxo, b'\x6a')  # OP_RETURN
    p2pkh_signature = tx_engine.get_legacy_sig(private_key, p2pkh_tx)

    # 6. Build scriptsig and put it in the input
    p2pkh_scriptsig = scriptsig_engine.p2pkh(p2pkh_signature, compressed_pubkey)
    final_tx = add_scriptsig(p2pkh_tx, p2pkh_scriptsig)

    # 7. Validate
    final_script = p2pkh_scriptsig + p2pkh_scriptpubkey
    asm = parser.parse_script(final_script)
    print(f"P2PKH ASM: {asm}")
    assert script_engine.eval_script(final_script, final_tx, input_index=0), "p2pkh scriptSig + scriptpubkey failed"
