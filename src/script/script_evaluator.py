"""
Class for the ScriptEvaluator: High-level API: validates UTXO spends using scriptSig, scriptPubKey, and possibly witness
"""

from src.db import BitCloneDatabase
from src.tx import Transaction


class ScriptEvaluator:
    """
    Validates UTXOs
    """

    def __init__(self, utxos: BitCloneDatabase):
        self.utxos = utxos

    def valiidate_utxo(self, tx: Transaction, input_index: int = 0):
        pass
