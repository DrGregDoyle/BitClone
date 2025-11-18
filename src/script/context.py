# context.py
from dataclasses import dataclass
from typing import Optional

__all__ = ["ExecutionContext"]


@dataclass
class ExecutionContext:
    tx: Optional['Transaction'] = None
    input_index: Optional[int] = None
    utxo: Optional['UTXO'] = None
    amount: Optional[int] = None  # For SegWit
    script_code: Optional[bytes] = None  # For P2SH/witness
    tapscript: bool = False
    sig_engine: Optional['SignatureEngine'] = None
    is_p2sh: bool = False
    is_segwit: bool = False
    merkle_root: bytes = None
