"""
The UTXO class
"""
from src.core import TX
from src.tx.tx import TxOutput

__all__ = ["UTXO"]


class UTXO:
    """
    Unspent Transaction Output - represents a spendable output
    """
    __slots__ = ("txid", "vout", "amount", "scriptpubkey", "block_height", "is_coinbase")

    def __init__(self, txid: bytes, vout: int, amount: int, scriptpubkey: bytes,
                 block_height: int = None, is_coinbase: bool = False):
        self.txid = txid
        self.vout = vout
        self.amount = amount
        self.scriptpubkey = scriptpubkey
        self.block_height = block_height
        self.is_coinbase = is_coinbase

    @classmethod
    def from_txoutput(cls, txid: bytes, vout: int, txoutput: TxOutput,
                      block_height: int = None, is_coinbase: bool = False):
        """Create UTXO from a TxOutput"""
        return cls(txid, vout, txoutput.amount, txoutput.scriptpubkey,
                   block_height, is_coinbase)

    def outpoint(self) -> bytes:
        """Return txid + vout for referencing. Will be key in the db."""
        return self.txid + self.vout.to_bytes(TX.VOUT, "little")

    def is_mature(self, current_height: int) -> bool:
        """Check if coinbase UTXO is mature (100 blocks)"""
        if not self.is_coinbase or self.block_height is None:
            return True
        return current_height - self.block_height >= 100

    def __eq__(self, other):
        if not isinstance(other, UTXO):
            return False
        return self.outpoint() == other.outpoint()

    def __hash__(self):
        return hash(self.outpoint())

    def __str__(self):
        return f"UTXO({self.txid.hex()[:8]}...:{self.vout}, {self.amount} sats)"
