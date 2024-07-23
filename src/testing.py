"""
Testing all components
"""
from random import randint

from src.cipher import encode_script
from src.database import Database
from src.engine import TxEngine
from src.library.hash_func import hash160, hash256
from src.script import ScriptEngine
from src.tx import UTXO, TxInput, TxOutput, Transaction, Outpoint
from src.wallet import Wallet
from tests.utility import random_outpoint, random_int, random_hex

DEFAULT_SEED_PHRASE = ['donate', 'dentist', 'negative', 'hub', 'pact', 'drama', 'wild', 'grocery', 'nerve', 'cycle',
                       'screen', 'hundred', 'bomb', 'law', 'walk', 'stamp', 'small', 'coast', 'arrest', 'element',
                       'echo', 'frame', 'vehicle', 'gain']


def generate_utxo(db: Database, wallet: Wallet):
    _outpoint = random_outpoint()

    height = randint(400000, 500000)
    amount = random_int(16)
    _pubkeyhash = hash160(wallet.compressed_public_key)
    _asm = ["OP_DUP", "OP_HASH160", "OP_PUSHBYTES_20", _pubkeyhash, "OP_EQUALVERIFY", "OP_CHECKSIG"]
    scriptpubkey = encode_script(_asm)
    utxo = UTXO(_outpoint, height, amount, scriptpubkey)
    db.post_utxo(utxo)


if __name__ == "__main__":
    db = Database(new_db=True)
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

    # print(tx.to_json())

    # Decode tx
    engine = ScriptEngine()
    witness0_verified = engine.witness_validation(tx, 0, _utxo0)
    print(witness0_verified)
    witness1_verified = engine.witness_validation(tx, 1, _utxo1)
    print(witness1_verified)

    # tx_data = "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000"
    # _decoded = decode_transaction(tx_data)
    # print(_decoded.to_json())
