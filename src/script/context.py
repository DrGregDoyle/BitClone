"""
We create the ExecutionContext: used for passing data within the scriptEngine and for tracking conditional operations


"""
from __future__ import annotations

from dataclasses import dataclass
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

    @property
    def utxo(self):
        if self.input_index is not None and self.utxos and self.input_index < len(self.utxos):
            return self.utxos[self.input_index]
        return None
