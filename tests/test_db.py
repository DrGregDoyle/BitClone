"""
We verify that we can add, get and remove utxos from the db
"""
from pathlib import Path
from random import randint, choice
from secrets import token_bytes

from src.database import BitCloneDatabase
from src.tx.tx import UTXO

TESTBD_PATH = Path(__name__).parent / "db_files" / "test_db.db"


# --- HELPER --- #

def random_utxo(is_coinbase: bool = False):
    return UTXO(
        txid=token_bytes(32), vout=randint(0, 16), amount=randint(10000, 1000000), scriptpubkey=token_bytes(20),
        block_height=randint(100000, 200000), is_coinbase=is_coinbase
    )


def test_utxo_ops():
    utxo_num = randint(5, 10)  # Min 5 UTXOS
    utxos = [random_utxo() for _ in range(utxo_num)]

    temp_db = BitCloneDatabase(TESTBD_PATH)
    temp_db.wipe_db()  # Ensure fresh db
    for u in utxos:
        temp_db.add_utxo(u)

    choice_utxo = choice(utxos)
    recovered_utxo = temp_db.get_utxo(choice_utxo.outpoint())
    assert recovered_utxo == choice_utxo, "Did not recover correct utxo for given outpoint"

    # Remove
    temp_db.remove_utxo(choice_utxo.outpoint())
    empty_utxo = temp_db.get_utxo(choice_utxo.outpoint())
    assert empty_utxo is None, "Did not remove random utxo"


def test_db_recovery():
    test_db = BitCloneDatabase(TESTBD_PATH)
    test_db.wipe_db()  # Fresh db

    # Get 5-10 random utxos
    utxos = [random_utxo() for _ in range(randint(5, 10))]
    # Add to database
    for u in utxos:
        test_db.add_utxo(u)

    # Load new database
    loaded_db = BitCloneDatabase(TESTBD_PATH)

    # Verify number of entries
    for t in utxos:
        assert loaded_db.get_utxo(t.outpoint()) == t, "Did not load random db properly"
