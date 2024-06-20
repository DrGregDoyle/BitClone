"""
The Database class
"""
# --- IMPORTS --- #
import logging
import sqlite3
import sys
import time
from pathlib import Path

from src.utility import random_tx_id, random_bool, random_amount, random_height, random_v_out, random_hash256
from src.utxo import UTXO, Outpoint, decode_outpoint, decode_utxo

# --- LOGGING --- #
log_level = logging.DEBUG
logger = logging.getLogger(__name__)
logger.setLevel(log_level)
logger.addHandler(logging.StreamHandler(stream=sys.stdout))

# --- CONSTANTS --- #
DB_DIR = Path(__file__).parent / "db"
DB_FILE = "utxo_set.db"

# --- QUERIES --- #
TABLE_EXEC = """CREATE TABLE utxo(outpoint TEXT NOT NULL PRIMARY KEY, utxo_value TEXT NOT NULL)"""
DELETE_EXEC = """DELETE FROM utxo"""
VACUUM_EXEC = """VACUUM"""
GET_UTXO_QUERY = """SELECT utxo_value FROM utxo where outpoint = (?)"""
POST_UTXO_QUERY = """INSERT INTO utxo VALUES(?,?)"""
DELETE_UTXO_QUERY = """DELETE FROM utxo WHERE outpoint = (?) RETURNING utxo_value"""  #


# --- CLASSES --- #

class Database:
    """
    The Database will consist of a key/value pair for each UTXO.
    """

    def __init__(self, db_dir: str | Path = DB_DIR, db_file: str = DB_FILE):
        # Setup file location
        self.db_dir = db_dir  # string
        temp_path = Path(self.db_dir)
        if not temp_path.is_dir():
            temp_path.mkdir(parents=True)
        self.db_dir_path = temp_path

        # Setup db file
        self.db_file = str((self.db_dir_path / db_file).absolute())

        # Create db
        self._create_db()

        # TODO: Setup memory option

    def _create_db(self):
        # Establish connection to db
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()

        # Create Table
        try:
            c.execute(TABLE_EXEC)
            conn.commit()
        except sqlite3.OperationalError:
            # logger.debug("Table already exists")
            pass

        # Exit gracefully
        conn.close()

    def _wipe_db(self):
        # Establish connection to db
        conn = sqlite3.connect(self.db_file, isolation_level=None)
        c = conn.cursor()

        # Truncate and vacuum
        try:
            c.execute(DELETE_EXEC)
            c.execute(VACUUM_EXEC)
        except sqlite3.OperationalError as e:
            logger.error(f"Error erasing utxo db: {e}")

        # Exit gracefully
        conn.close()

    def query_db(self, query: str, data=None):
        with sqlite3.connect(self.db_file) as conn:
            # Cursor
            c = conn.cursor()

            # Query
            query_over = False
            while not query_over:
                try:
                    c.execute(query, data) if data else c.execute(query)
                    conn.commit()
                    result = c.fetchall()
                    query_over = True
                # Key collision
                except sqlite3.IntegrityError as e1:
                    logger.debug("Key value already exists in db")
                    result = e1
                    query_over = True
                # DB Locked
                except sqlite3.OperationalError as e2:
                    # logger.debug(f"Operational error: {e2}")
                    # logger.debug(f"Current query: {query}")
                    time.sleep(0.01)
        return result

    # --- API --- #

    def post_utxo(self, utxo: str | UTXO):
        # Get utxo
        _utxo = decode_utxo(utxo) if isinstance(utxo, str) else utxo

        # Query
        data_tuple = (_utxo.key, _utxo.value)
        error_msg = self.query_db(POST_UTXO_QUERY, data_tuple)
        if error_msg:
            logger.error(f"Post UTXO failed: {error_msg}")
            return False
        else:
            return True

    def get_utxo(self, outpoint: str | Outpoint):
        # Get outpoint key
        _outpoint = decode_outpoint(outpoint) if isinstance(outpoint, str) else outpoint

        # Query
        value = self.query_db(GET_UTXO_QUERY, (_outpoint.encoded,))
        if value and isinstance(value, list):
            v = value[0][0]
            return v
        return value  # Will return empty list

    def delete_utxo(self, utxo: str | UTXO) -> bool:
        # Get utxo
        _utxo = decode_utxo(utxo) if isinstance(utxo, str) else utxo

        # Verify UTXO
        utxo_value = self.get_utxo(_utxo.outpoint)
        if not utxo_value:
            logger.debug(f"No UTXO found with given outpoint")
            return False

        # Query
        self.query_db(DELETE_UTXO_QUERY, (_utxo.key,))
        # logger.debug(f"UTXO DELETED: {_utxo.to_json()}")
        return True


# --- TESTING --- #
if __name__ == "__main__":
    test_db = Database()

    # Outpoint
    tx_id = random_tx_id()
    v_out1 = random_v_out()
    v_out2 = random_v_out()

    # tx_id = hash256("GREG")
    # v_out1 = 16
    # v_out2 = 32
    outpoint = Outpoint(tx_id=tx_id, v_out=v_out1)
    fake_outpoint = Outpoint(tx_id=tx_id, v_out=v_out2)

    # Value
    height = random_height()
    amount = random_amount()
    locking_code = random_hash256(128)
    coinbase = random_bool()
    not_coinbase = not coinbase
    # height = 0x00FFFF00
    # amount = 0xFF0000FF
    # locking_code = hash256("MATH")
    # coinbase = True
    # not_coinbase = False

    utxo = UTXO(outpoint=outpoint, height=height, amount=amount, locking_code=locking_code, coinbase=coinbase)
    utxo_false = UTXO(outpoint=outpoint, height=height, amount=amount, locking_code=locking_code, coinbase=not_coinbase)

    # Test db
    print(f"OUTPOINT: {outpoint.to_json()}")
    print(f"UTXO: {utxo.to_json()}")
    print(f"UTXO KEY: {utxo.key}")
    print(f"UTXO VALUE: {utxo.value}")
    print(f"POST UTXO: {test_db.post_utxo(utxo)}")
    print(f"GET UTXO: {test_db.get_utxo(utxo.outpoint)}")
    print(f"GET FAKE UTXO: {test_db.get_utxo(fake_outpoint)}")
    # print(f"DELETE UTXO: {test_db.delete_utxo(utxo)}")
    # print(f"DELETE FAKE UTXO: {test_db.delete_utxo(utxo_false)}")