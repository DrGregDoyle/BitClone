"""
Testing all components
"""
from random import randint

from src.cipher import encode_script, encode_base58check
from src.database import Database
from src.library.hash_func import hash160
from src.tx import UTXO
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
    hashval = "a81c3e53957edb50a3ac6bfcaced0c99756b45e1"
    print(encode_base58check(hashval, 0))
