"""
A file for testing db
"""
from pathlib import Path

from src.database import Database
from tests.backup.utility import random_utxo, random_int

DB_DIR = Path(__file__).parent / "db"


def test_db():
    # Create new db
    _db = Database(db_dir=DB_DIR, db_file="utxo_test_set.db", new_db=True)

    # Post UTXOS
    random_range = random_int(4)
    utxo_list = [random_utxo() for _ in range(random_range)]
    for utxo in utxo_list:
        _db.post_utxo(utxo)

    count_query = """SELECT COUNT(*) FROM utxo"""
    query_result = _db.query_db(count_query)[0][0]
    assert query_result == len(utxo_list)

    # Get UTXOS
    for utxo_g in utxo_list:
        _utxo = _db.get_utxo(utxo_g.key)
        assert _utxo.bytes == utxo_g.bytes
