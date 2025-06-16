from dataclasses import dataclass

from src.data import to_little_bytes, write_compact_size

# from src.tx import Output

__all__ = ["UTXO"]


@dataclass
class UTXO:
    txid: bytes  # Transaction ID that created this UTXO
    vout: int  # Output index in the transaction
    amount: int  # Amount in satoshis
    script_pubkey: bytes  # Script that locks this output
    spent: bool = False  # Indicates whether the UTXO has been spent (default is False)

    @classmethod
    def from_tuple(cls, data: tuple):
        """
        Creates UTXO from db entry
        """
        txid, vout, amount, script_pubkey, spent = data
        return cls(txid, vout, amount, script_pubkey, bool(spent))

    def to_dict(self) -> dict:
        """Converts the UTXO to a dictionary."""
        return {
            "txid": self.txid.hex(),
            "vout": self.vout,
            "amount": self.amount,
            "script_pubkey": self.script_pubkey.hex(),
            "spent": self.spent
        }

    def to_output_bytes(self) -> bytes:
        """
        Returns amount + scriptpubkey_size + scriptpubkey, suitable for use in Output.from_bytes() constructor
        """
        return to_little_bytes(self.amount, 8) + write_compact_size(len(self.script_pubkey)) + self.script_pubkey
