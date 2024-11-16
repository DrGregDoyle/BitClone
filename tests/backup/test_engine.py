"""
Tests for ScriptEngine
"""
from pathlib import Path
from random import randint

from src.cipher import encode_script
from src.database import Database
from src.engine import TxEngine
from src.backup.library.hash_func import hash256, hash160
from src.script import ScriptEngine
from src.tx import Outpoint, UTXO, TxInput, TxOutput, Transaction
from src.wallet import Wallet
from tests.backup.utility import random_hex

DEFAULT_SEED_PHRASE = ['donate', 'dentist', 'negative', 'hub', 'pact', 'drama', 'wild', 'grocery', 'nerve', 'cycle',
                       'screen', 'hundred', 'bomb', 'law', 'walk', 'stamp', 'small', 'coast', 'arrest', 'element',
                       'echo', 'frame', 'vehicle', 'gain']

DB_DIR = Path(__file__).parent / "db"


def test_legacy_p2pkh():
    db = Database(db_dir=DB_DIR, db_file="utxo_test_set.db", new_db=True)
    w = Wallet(DEFAULT_SEED_PHRASE)
    e = TxEngine(db, w.keypair)

    # Add known UTXOS
    _hexseed = random_hex()
    tx_id = hash256(_hexseed)
    # Outpoints
    _pt0 = Outpoint(tx_id, 0)
    _pt1 = Outpoint(tx_id, 1)
    # Height, amount
    _height = randint(400000, 500000)
    _amount = 0x10
    _pubkeyhash = hash160(w.compressed_public_key)
    _asm = ["OP_DUP", "OP_HASH160", "OP_PUSHBYTES_20", _pubkeyhash, "OP_EQUALVERIFY", "OP_CHECKSIG"]
    _scriptpubkey = encode_script(_asm)
    _utxo0 = UTXO(_pt0, _height, _amount, _scriptpubkey)
    _utxo1 = UTXO(_pt1, _height, _amount, _scriptpubkey)
    utxos = [_utxo0, _utxo1]
    db.post_utxo(_utxo0)
    db.post_utxo(_utxo1)

    # Create Transaction
    _output_amount = 0x1F
    _input0 = TxInput(_utxo0.outpoint, "")  # Unsigned inputs
    _input1 = TxInput(_utxo1.outpoint, "")
    _output0 = TxOutput(_output_amount, _scriptpubkey)
    tx = Transaction([_input0, _input1], [_output0])

    # Sign Tx
    for n in range(2):
        tx = e.sign_tx_p2pkh(tx, n)  # Sign each input

    # Create scripts
    _scriptpubkey0 = _utxo0.scriptpubkey.hex()
    _scriptsig0 = tx.inputs[0].scriptsig.hex()
    _script0 = _scriptsig0 + _scriptpubkey0

    _scriptpubkey1 = _utxo1.scriptpubkey.hex()
    _scriptsig1 = tx.inputs[1].scriptsig.hex()
    _script1 = _scriptsig1 + _scriptpubkey1
    script_list = [_script0, _script1]

    s = ScriptEngine()
    for script in script_list:
        i = script_list.index(script)
        s.parse_script(script, tx, i, utxos[i])
        tx_verified = s.main_stack.pop()
        assert tx_verified
        assert s.main_stack.height == 0


def test_segwit_p2wpkh():
    db = Database(db_dir=DB_DIR, db_file="utxo_test_set.db", new_db=True)
    w = Wallet(DEFAULT_SEED_PHRASE)
    e = TxEngine(db, w.keypair)

    # Add known UTXOS
    _hexseed = random_hex()
    tx_id = hash256(_hexseed)
    # Outpoints
    _pt0 = Outpoint(tx_id, 0)
    _pt1 = Outpoint(tx_id, 1)
    # Height, amount
    _height = randint(400000, 500000)
    _amount = 0x10
    _pubkeyhash = hash160(w.compressed_public_key)
    _asm = ["OP_0", "OP_PUSHBYTES_20", _pubkeyhash]  # P2WPKH
    _scriptpubkey = encode_script(_asm)
    _utxo0 = UTXO(_pt0, _height, _amount, _scriptpubkey)
    _utxo1 = UTXO(_pt1, _height, _amount, _scriptpubkey)
    utxos = [_utxo0, _utxo1]
    db.post_utxo(_utxo0)
    db.post_utxo(_utxo1)

    # Create Transaction
    _output_amount = 0x1F
    _input0 = TxInput(_utxo0.outpoint, "")  # Unsigned inputs
    _input1 = TxInput(_utxo1.outpoint, "")
    _output0 = TxOutput(_output_amount, _scriptpubkey)
    tx = Transaction([_input0, _input1], [_output0])

    # Sign Tx

    for n in range(2):
        tx = e.sign_tx_p2wpkh(tx, n)

    # Decode tx
    engine = ScriptEngine()
    for x in range(2):
        _utxo = utxos[x]
        assert engine.witness_validation(tx, x, _utxo)
