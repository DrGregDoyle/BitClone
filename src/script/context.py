"""
We create the ExecutionContext: used for passing data within the scriptEngine and for tracking conditional operations


"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List

__all__ = ["ExecutionContext"]


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

    # Conditional execution state
    executing: bool = True  # Whether we're currently executing opcodes
    branch_stack: List[bool] = field(default_factory=list)  # Stack tracking branch execution
