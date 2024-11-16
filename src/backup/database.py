"""
The Database class
"""
# --- IMPORTS --- #
import logging
import sqlite3
import sys
import time
from pathlib import Path

from src.cipher import decode_utxo, decode_outpoint
from src.tx import UTXO, Outpoint

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
DELETE_UTXO_QUERY = """DELETE FROM utxo WHERE outpoint = (?) RETURNING utxo_value"""
HEIGHT_QUERY = """SELECT COUNT(1) FROM utxo"""
KEY_QUERY = """SELECT outpoint FROM utxo """
VALUE_QUERY = """SELECT utxo_value from utxo"""


# --- CLASSES --- #

class Database:
    """
    The Database will consist of a key/value pair for each UTXO.
    """

    def __init__(self, db_dir: str | Path = DB_DIR, db_file: str = DB_FILE, new_db=False):
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

        # New db
        if new_db:
            self._wipe_db()

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
                    logger.debug(f"Operational error: {e2}")
                    logger.debug(f"Current query: {query}")
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

    def get_utxo(self, outpoint: str | Outpoint) -> UTXO | list:
        # Get outpoint key
        _outpoint = decode_outpoint(outpoint) if isinstance(outpoint, str) else outpoint

        # Query
        value = self.query_db(GET_UTXO_QUERY, (_outpoint.hex,))
        if value and isinstance(value, list):
            v = value[0][0]
            return decode_utxo(_outpoint.hex + v)
        return []

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

    def get_height(self):
        # Query
        height = self.query_db(HEIGHT_QUERY)[0][0]
        return height

    def get_outpoints(self):
        # Query
        _outpoint_list = self.query_db(KEY_QUERY)
        return [t[0] for t in _outpoint_list]

    def get_values(self):
        # Query
        _value_list = self.query_db(VALUE_QUERY)
        return [v[0] for v in _value_list]
