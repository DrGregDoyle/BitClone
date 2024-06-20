"""
The Database class
"""
# --- IMPORTS --- #
import logging
import sqlite3
import sys
from pathlib import Path

# --- LOGGING --- #
log_level = logging.DEBUG
logger = logging.getLogger(__name__)
logger.setLevel(log_level)
logger.addHandler(logging.StreamHandler(stream=sys.stdout))

# --- CONSTANTS --- #
DB_DIR = Path(__file__).parent / "db"
DB_FILE = "utxo_set.db"

TABLE_EXEC = """CREATE TABLE utxo(key text, value text)"""


# --- CLASSES --- #

class Database:
    """
    The Database will consist of a key/value pair for each UTXO.

    Table: utxo
    Columns:    key (outpoint)  | value (utxo.value)
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

        # TODO: Setup memory option

    def _create_db(self):
        # Establish connection to db
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()

        # Create Table
        c.execute(TABLE_EXEC)
        conn.commit()

        # Exit gracefully
        conn.close()


# --- TESTING --- #
if __name__ == "__main__":
    test_db = Database()
    test_db._create_db()
