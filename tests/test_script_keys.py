"""
Tests for verifying that various script_sig + script_pub_keys will evaluate to True in the script engine
"""

from secrets import randbits

import pytest

from src.crypto import secp256k1
from src.data import compress_public_key, write_compact_size
from src.db import BitCloneDatabase
from src.script import ScriptEngine, TxEngine, ScriptPubKeyEngine, ScriptSigEngine, ScriptParser
from src.tx import UTXO, Transaction, Input, Output


@pytest.fixture(scope="module")
def test_db(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("db") / "test_script_keys.db"
    db = BitCloneDatabase(db_path)
    # optional: seed test data here if needed
    return db


@pytest.fixture
def script_engine(test_db):
    return ScriptEngine(db=test_db)


@pytest.fixture
def tx_engine(test_db):
    return TxEngine(db=test_db)


@pytest.fixture
def pubkey_engine():
    return ScriptPubKeyEngine()


@pytest.fixture
def scriptsig_engine():
    return ScriptSigEngine()


@pytest.fixture
def parser():
    return ScriptParser()


@pytest.fixture
def curve():
    return secp256k1()


def test_p2pk(script_engine, tx_engine, curve, pubkey_engine, test_db, scriptsig_engine, parser):
    """
    Minimal Flow for a P2PK Test:
        -Generate a private key.
        -Derive a public key and its P2PK scriptPubKey.
        -Create a mock UTXO with that scriptPubKey.
        -Create a tx spending that UTXO and sign it.
        -Feed it to the ScriptEngine for validation.
    """
    # 1. Generate a valid private key
    private_key = 0
    while not (1 <= private_key < curve.order):
        private_key = randbits(256)

    # 2. Get public key and p2pk scriptPubkey
    pubkey_point = curve.multiply_generator(private_key)
    compressed_pubkey = compress_public_key(pubkey_point)
    p2pk_scriptpubkey = pubkey_engine.p2pk(pubkey=compressed_pubkey).scriptpubkey
    print(f"SCRIPT PUBKEY: {p2pk_scriptpubkey.hex()}")

    # 3. Create mock UTXO with given scriptpubkey
    test_utxo = UTXO(
        txid=bytes.fromhex("f" * 64),
        vout=0,
        amount=50000,
        script_pubkey=p2pk_scriptpubkey
    )
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
    p2pk_asm = parser.parse_script(final_script)
    print(f"P2PK ASM: {p2pk_asm}")
    assert script_engine.eval_script(final_script, test_tx, input_index=0), "p2pk scriptSig + scriptpubkey failed " \
                                                                            "validation"
