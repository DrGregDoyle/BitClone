"""
AddressBook - manages derived addresses, UTXO tracking, and gap limit scanning
"""
import json
from dataclasses import dataclass, field

from src.tx.tx import UTXO
from src.wallet.derivation import DerivationPath

__all__ = ["DerivedAddress", "AddressBook"]

# --- CONSTANTS --- #
GAP_LIMIT = 20


@dataclass
class DerivedAddress:
    bip: DerivationPath
    account: int
    change: int
    index: int
    address: str
    pubkey: bytes
    used: bool = False
    utxos: list[UTXO] = field(default_factory=list)

    @property
    def path(self) -> str:
        return self.bip.path(self.account, self.change, self.index)

    @property
    def balance(self) -> int:
        return sum(u.amount for u in self.utxos)

    def to_dict(self) -> dict:
        return {
            "bip": self.bip.name,
            "account": self.account,
            "change": self.change,
            "index": self.index,
            "address": self.address,
            "pubkey": self.pubkey.hex(),
            "used": self.used,
            "utxos": [
                {
                    "outpoint": u.outpoint.hex(),
                    "amount": u.amount,
                    "scriptpubkey": u.scriptpubkey.hex(),
                    "block_height": u.block_height,
                    "is_coinbase": u.is_coinbase
                }
                for u in self.utxos
            ]
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DerivedAddress":
        utxos = [
            UTXO(
                outpoint=u["outpoint"],
                amount=u["amount"],
                scriptpubkey=bytes.fromhex(u["scriptpubkey"]),
                block_height=u.get("block_height"),
                is_coinbase=u.get("is_coinbase", False)
            )
            for u in data.get("utxos", [])
        ]
        return cls(
            bip=DerivationPath[data["bip"]],
            account=data["account"],
            change=data["change"],
            index=data["index"],
            address=data["address"],
            pubkey=bytes.fromhex(data["pubkey"]),
            used=data["used"],
            utxos=utxos
        )


class AddressBook:
    """
    Manages all derived addresses for a wallet.
    Keyed by address string for fast UTXO → signing key lookup.
    """

    def __init__(self, gap_limit: int = GAP_LIMIT):
        self._book: dict[str, DerivedAddress] = {}
        self.gap_limit = gap_limit

    # --- CORE CRUD --- #

    def add(self, derived_address: DerivedAddress) -> None:
        """Register a newly derived address"""
        self._book[derived_address.address] = derived_address

    def remove(self, address: str) -> None:
        """Remove an address from the book"""
        if address not in self._book:
            raise KeyError(f"Address {address} not found in AddressBook")
        del self._book[address]

    def get(self, address: str) -> DerivedAddress:
        """Lookup a DerivedAddress by address string"""
        if address not in self._book:
            raise KeyError(f"Address {address} not found in AddressBook")
        return self._book[address]

    def __contains__(self, address: str) -> bool:
        """
        Allows for the use keyword "in" to search within book.
        """
        return address in self._book

    def __len__(self) -> int:
        return len(self._book)

    # --- STATUS UPDATES --- #

    def mark_used(self, address: str) -> None:
        """Mark an address as having appeared on-chain"""
        self.get(address).used = True

    def update_utxos(self, address: str, utxos: list[UTXO]) -> None:
        """Replace the UTXO set for a given address after a network refresh"""
        entry = self.get(address)
        entry.utxos = utxos
        if utxos:
            entry.used = True  # If it has UTXOs it's definitely been used

    # --- QUERIES --- #

    def get_unused(self, bip: DerivationPath, change: int, account: int = 0) -> list[DerivedAddress]:
        """
        Return all unused addresses for a given script type and change/external branch.
        Used by the gap limit scanner.
        """
        return [
            entry for entry in self._book.values()
            if entry.bip == bip
               and entry.change == change
               and entry.account == account
               and not entry.used
        ]

    def get_all_utxos(self) -> list[UTXO]:
        """Return all spendable UTXOs across all addresses — feeds into TxBuilder"""
        utxos = []
        for entry in self._book.values():
            utxos.extend(entry.utxos)
        return utxos

    def get_signing_path(self, address: str) -> str:
        """
        Given a UTXO's address, return the derivation path needed to re-derive
        the private key for signing
        """
        return self.get(address).path

    def next_index(self, bip: DerivationPath, change: int, account: int = 0) -> int:
        """
        Return the next unused index for a given branch.
        Used when deriving fresh addresses.
        """
        indices = [
            entry.index for entry in self._book.values()
            if entry.bip == bip
               and entry.change == change
               and entry.account == account
        ]
        return max(indices) + 1 if indices else 0

    def gap_count(self, bip: DerivationPath, change: int, account: int = 0) -> int:
        """
        Count consecutive unused addresses from the highest index downward.
        When this reaches gap_limit, scanning can stop.
        """
        entries = sorted(
            [e for e in self._book.values()
             if e.bip == bip and e.change == change and e.account == account],
            key=lambda e: e.index,
            reverse=True
        )
        count = 0
        for entry in entries:
            if not entry.used:
                count += 1
            else:
                break
        return count

    def should_stop_scanning(self, bip: DerivationPath, change: int, account: int = 0) -> bool:
        """Returns True when the gap limit has been reached for a given branch"""
        return self.gap_count(bip, change, account) >= self.gap_limit

    # --- BALANCE --- #

    def balance(self) -> int:
        """Total spendable balance across all addresses in satoshis"""
        return sum(entry.balance for entry in self._book.values())

    def balance_by_bip(self) -> dict[str, int]:
        """Balance broken down by script type"""
        result = {}
        for entry in self._book.values():
            key = entry.bip.name
            result[key] = result.get(key, 0) + entry.balance
        return result

    # --- PERSISTENCE --- #

    def to_json(self) -> str:
        """Serialize the address book to JSON for storage"""
        return json.dumps(
            {address: entry.to_dict() for address, entry in self._book.items()},
            indent=2
        )

    @classmethod
    def from_json(cls, data: str, gap_limit: int = GAP_LIMIT) -> "AddressBook":
        """Restore an AddressBook from a JSON string"""
        book = cls(gap_limit=gap_limit)
        for entry_data in json.loads(data).values():
            book.add(DerivedAddress.from_dict(entry_data))
        return book

    def save(self, filepath: str) -> None:
        """Save the address book to a JSON file"""
        with open(filepath, "w") as f:
            f.write(self.to_json())

    @classmethod
    def load(cls, filepath: str, gap_limit: int = GAP_LIMIT) -> "AddressBook":
        """Load an AddressBook from a JSON file"""
        with open(filepath, "r") as f:
            return cls.from_json(f.read(), gap_limit)
