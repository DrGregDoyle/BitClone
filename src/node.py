"""
Class file for Node
"""
from pathlib import Path

from src.blockchain import Blockchain
from src.db import DB_PATH
from src.script import script_engine
from src.tx import Transaction


class Node:
    """
    The Node class for BitClone
    """

    def __init__(self, db_path: Path = DB_PATH):
        self.blockchain = Blockchain(db_path)
        self.script_engine = script_engine
        self.mempool = []

    def validate_tx(self, tx: Transaction):
        """
        For each input in the tx, we find the corresponding utxo and evaluate the attached scriptpubkey with the
        scriptsig from the input
        """
        for i in tx.inputs:
            # Get UTXO
            utxo = self.blockchain.db.get_utxo(txid=i.txid, vout=i.vout)
