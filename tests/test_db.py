"""
A file for testing db
"""

from src.database import Database
from src.utility import *
from src.utxo import Outpoint, UTXO


def random_utxo():
    tx_id = random_tx_id()
    v_out = random_v_out()
    outpoint = Outpoint(tx_id, v_out)

    height = random_height()
    amount = random_amount()
    locking_code = random_hash256(128)
    coinbase = random_bool()

    return UTXO(outpoint=outpoint, height=height, amount=amount, locking_code=locking_code, coinbase=coinbase)


def test_db():
    # Create new db
    _db = Database()
    _db._wipe_db()

    # Post UTXOS
    random_range = random.randint(5, 15)
    utxo_list = [random_utxo() for _ in range(random_range)]
    for utxo in utxo_list:
        _db.post_utxo(utxo)

    count_query = """SELECT COUNT(*) FROM utxo"""
    query_result = _db.query_db(count_query)[0][0]
    assert query_result == len(utxo_list)

    # Get UTXOS
    for utxo_g in utxo_list:
        value = _db.get_utxo(utxo_g.key)
        assert value == utxo_g.value

    # Delete UTXOS
    for utxo_d in utxo_list:
        utxo_deleted = _db.delete_utxo(utxo_d)
        assert utxo_deleted
