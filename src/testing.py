"""
Testing all components
"""
from random import randint

from src.cipher import decode_outpoint, encode_script
from src.database import Database
from src.engine import TxEngine
from src.library.hash_func import hash160
from src.script import ScriptEngine
from src.tx import UTXO, TxInput, TxOutput, Transaction
from src.wallet import Wallet
from tests.utility import random_outpoint, random_int

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
    db = Database()
    w = Wallet(DEFAULT_SEED_PHRASE)
    e = TxEngine(db, w.keypair)
    # for _ in range(5):
    #     generate_utxo(db, w)
    _outpoints = [decode_outpoint(t) for t in db.get_outpoints()]
    _utxos = []
    for t in _outpoints:
        utxo = db.get_utxo(t)
        _utxos.append(utxo)

    _pubkeyhash = hash160(w.compressed_public_key)
    _asm = ["OP_DUP", "OP_HASH160", "OP_PUSHBYTES_20", _pubkeyhash, "OP_EQUALVERIFY", "OP_CHECKSIG"]
    scriptpubkey = encode_script(_asm)
    utxo0 = _utxos[0]
    outpoint0 = utxo0.outpoint
    amount0 = utxo0.amount.num
    input0 = TxInput(outpoint0, "")
    utxo1 = _utxos[1]
    outpoint1 = utxo1.outpoint
    amount1 = utxo1.amount.num
    input1 = TxInput(outpoint1, "")

    output_amout_min = min(amount0, amount1)
    output_amount = randint(output_amout_min, amount0 + amount1)
    output0 = TxOutput(output_amount, scriptpubkey=scriptpubkey)
    tx = Transaction([input0, input1], [output0])

    for n in range(tx.input_count.num):
        tx = e.sign_tx_p2pkh(tx, n)
        # print(f"TX: {n}")
        # print(tx.to_json())

    _scriptpubkey0 = utxo0.scriptpubkey.hex()
    _scriptsig0 = tx.inputs[0].scriptsig.hex()
    _script0 = _scriptsig0 + _scriptpubkey0

    _scriptpubkey1 = utxo1.scriptpubkey.hex()
    _scriptsig1 = tx.inputs[1].scriptsig.hex()
    _script1 = _scriptsig1 + _scriptpubkey1

    script_list = [_script0, _script1]

    s = ScriptEngine()
    s.parse_script(_script0, tx, input_index=0, utxo=utxo0)
    tx1_verified = s.main_stack.pop()  # Should pop stack and leave empty main stack
    if s.main_stack.height != 0:
        print(f"ELEMENT LEFT ON STACK")
        s.clear_stacks()
    s.parse_script(_script1, tx, input_index=1, utxo=utxo1)
    tx2_verified = s.main_stack.pop()
    if s.main_stack.height != 0:
        print(f"ELEMENT LEFT ON STACK")

    print(f"TxInput0 verified: {tx1_verified}")
    print(f"TxInput1 verified: {tx2_verified}")
