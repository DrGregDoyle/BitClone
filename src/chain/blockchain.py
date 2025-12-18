"""
The Blockchain class
"""
from pathlib import Path

from src.database.database import BitCloneDatabase, DB_PATH


# DB_PATH = Path(__file__).parent.parent / "database" / "db_files" / "chain.db"

class Blockchain:

    def __init__(self, db_path: Path = DB_PATH):
        self.db = BitCloneDatabase(db_path)
