"""
We verify that we can add, get and remove utxos from the db
"""
from pathlib import Path
from random import randint, choice
from secrets import token_bytes

from src.database import BitCloneDatabase
from src.tx import UTXO

TESTBD_PATH = Path(__name__).parent / "db_files" / "test_db.db"


def test_utxo_ops():
    utxo_num = randint(5, 10)  # Min 5 UTXOS
    utxos = []
    for x in range(utxo_num):
        txid = token_bytes(32)
        vout = randint(0, 16)
        amount = randint(10000, 100000)
        scriptpubkey = token_bytes(20)
        height = randint(500, 1000)
        is_coinbase = True if x == 0 else False
        utxos.append(UTXO(txid, vout, amount, scriptpubkey, height, is_coinbase))

    temp_db = BitCloneDatabase(TESTBD_PATH)
    temp_db.wipe_db()  # Ensure fresh db
    for u in utxos:
        temp_db.add_utxo(u)

    random_utxo = choice(utxos)
    recovered_utxo = temp_db.get_utxo(random_utxo.outpoint())
    assert recovered_utxo == random_utxo, "Did not recover correct utxo for given outpoint"

    # Remove
    temp_db.remove_utxo(random_utxo.outpoint())
    empty_utxo = temp_db.get_utxo(random_utxo.outpoint())
    assert empty_utxo is None, "Did not remove random utxo"
