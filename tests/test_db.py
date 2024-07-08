"""
A file for testing db
"""
from pathlib import Path

from src.database import Database
from tests.utility import random_utxo

DB_DIR = Path(__file__).parent / "db"


def test_db():
    # Create new db
    _db = Database(db_dir=DB_DIR, db_file="utxo_test_set.db")
    _db._wipe_db()

    # Post UTXOS
    utxo_list = [random_utxo()]  # [random_utxo() for _ in range(random_range)]
    for utxo in utxo_list:
        _db.post_utxo(utxo)
        # print(f"RANDOM UTXO")
        # print(f"TXID: {utxo.outpoint.txid}")
        # print(f"VOUT: {utxo.outpoint.v_out}")

    count_query = """SELECT COUNT(*) FROM utxo"""
    query_result = _db.query_db(count_query)[0][0]
    assert query_result == len(utxo_list)

    # Get UTXOS
    for utxo_g in utxo_list:
        value = _db.get_utxo(utxo_g.key)
        assert value == utxo_g.value
    #
    # # Delete UTXOS
    # for utxo_d in utxo_list:
    #     utxo_deleted = _db.delete_utxo(utxo_d)
    #     assert utxo_deleted
