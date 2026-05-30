"""
We create the ExecutionContext: used for passing data within the scriptEngine and for tracking conditional operations


"""
from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import Optional

__all__ = ["ExecutionContext"]


@dataclass(frozen=True)
class ExecutionContext:
    tx: Optional['Tx'] = None
    input_index: Optional[int] = None
    utxos: Optional[list['UTXO']] = None
    script_code: Optional[bytes] = None  # For P2SH/witness
    tapscript: bool = False
    is_segwit: bool = False
    merkle_root: Optional[bytes] = None

    def with_script_code(self, script_code: bytes) -> 'ExecutionContext':
        """Returns a new ExecutionContext with the given script_code set."""
        return replace(self, script_code=script_code)

    @property
    def utxo(self):
        if self.input_index is not None and self.utxos and self.input_index < len(self.utxos):
            return self.utxos[self.input_index]
        return None

    def to_dict(self) -> dict:
        """
        Returns dict of current values
        """
        return {
            "tx": self.tx.to_dict() if self.tx is not None else None,
            "input_index": self.input_index if self.input_index is not None else None,
            "utxos": [u.to_dict() for u in self.utxos] if self.utxos is not None else None,
            "script_code": self.script_code.hex() if self.script_code is not None else None,
            "tapscript": self.tapscript,
            "is_segwit": self.is_segwit,
            "merkle_root": self.merkle_root.hex() if self.merkle_root is not None else None,
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)
