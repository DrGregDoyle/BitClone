# context.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = ["ExecutionContext", "SignatureContext"]

from src.tx import Transaction


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
    utxo_list: Optional[list['UTXO']] = None


@dataclass(slots=True)
class SignatureContext:
    # TODO: Break up signature context into types: legacy, segwit and taproot
    """Holds all data needed to compute a signature hash for a specific input."""
    # Always needed
    tx: "Transaction"
    input_index: int
    sighash_type: int = 1

    # Legacy / SegWit v0
    script_code: Optional[bytes] = None  # scriptpubkey for legacy; witness script for v0
    amount: Optional[int] = None  # satoshis (required for v0 and Taproot)

    # Taproot (BIP341/342)
    ext_flag: int = 0  # 0=key-path, 1=script-path
    annex: Optional[bytes] = None  # must start with 0x50 if present
    merkle_root: Optional[bytes] = None  # leaf_hash if key-path
    leaf_hash: Optional[bytes] = None  # For use in script-path
    leaf_version: int = 0xC0  # tapscript v0 default
    pubkey_version: bytes = b'\x00'  # Available for future update
    codesep_pos: bytes = b'\xff\xff\xff\xff'  # To be adjusted based on script
    pubkey: Optional[bytes] = None  # To create extension for script-path

    # Optional caches (pass precomputed hashes to avoid recompute)
    prevouts_hash: Optional[bytes] = None
    sequences_hash: Optional[bytes] = None
    outputs_hash: Optional[bytes] = None

    # Optional for non-ANYONECANPAY global hashes
    amounts: Optional[list[int]] = None  # len == len(tx.inputs)
    prev_scriptpubkeys: Optional[list[bytes]] = None  # len == len(tx.inputs)
