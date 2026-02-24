"""
The DerivationPath class for use in the Wallet
"""
from enum import Enum

from src.script.script_types import P2PKH_Key, P2WPKH_Key, P2TR_Key, P2SH_Key

__all__ = ["DerivationPath"]


class DerivationPath(Enum):
    BIP44 = (44, "P2PKH")
    BIP49 = (49, "P2SH_P2WPKH")
    BIP84 = (84, "P2WPKH")
    BIP86 = (86, "P2TR")

    def __init__(self, purpose: int, script_type: str):
        self.purpose = purpose
        self.script_type = script_type

    def path(self, account: int = 0, change: int = 0, index: int = 0) -> str:
        # Coin value in path hardcoded to be 0 (BTC)
        return f"m/{self.purpose}'/0'/{account}'/{change}/{index}"

    def address(self, pubkey: bytes) -> str:
        match self:
            case DerivationPath.BIP44:
                return P2PKH_Key(pubkey).address
            case DerivationPath.BIP49:
                return P2SH_Key.from_data(P2WPKH_Key(pubkey).script).address
            case DerivationPath.BIP84:
                return P2WPKH_Key(pubkey).address
            case DerivationPath.BIP86:
                return P2TR_Key(pubkey).address
