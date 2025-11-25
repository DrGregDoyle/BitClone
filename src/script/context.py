# context.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = ["ExecutionContext"]

from src.tx import Transaction


@dataclass(frozen=True)
class ExecutionContext:
    tx: Optional['Transaction'] = None
    input_index: Optional[int] = None
    utxo: Optional['UTXO'] = None
    script_code: Optional[bytes] = None  # For P2SH/witness
    tapscript: bool = False
    is_segwit: bool = False
    merkle_root: bytes = None
    utxo_list: Optional[list['UTXO']] = None
