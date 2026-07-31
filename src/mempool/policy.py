"""Mempool admission outcomes and transaction standardness policy."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from src.core import ScriptPubKeyError
from src.script import classify_scriptpubkey
from src.tx import Tx


class AdmissionCategory(str, Enum):
    """Stable categories for callers that need more than a boolean result."""

    ACCEPTED = "accepted"
    ORPHAN = "orphan"
    CONSENSUS_INVALID = "consensus-invalid"
    NONSTANDARD = "nonstandard"
    POLICY = "policy"


@dataclass(frozen=True, slots=True)
class AdmissionResult:
    """The result of evaluating one transaction for mempool admission."""

    accepted: bool
    category: AdmissionCategory
    reason: str
    replaced_txids: tuple[bytes, ...] = ()


MAX_STANDARD_TX_WEIGHT = 400_000
MAX_STANDARD_SCRIPTSIG_SIZE = 1_650
MAX_STANDARD_NULL_DATA_SIZE = 83
STANDARD_TX_VERSIONS = frozenset({1, 2, 3})
OP_RETURN = 0x6A


def check_transaction_standardness(tx: Tx) -> str | None:
    """Return a policy rejection reason, or ``None`` for a standard shape."""
    if tx.version not in STANDARD_TX_VERSIONS:
        return f"non-standard transaction version {tx.version}"
    if tx.wu > MAX_STANDARD_TX_WEIGHT:
        return f"transaction weight {tx.wu} exceeds standard limit {MAX_STANDARD_TX_WEIGHT}"
    for txin in tx.inputs:
        if len(txin.scriptsig) > MAX_STANDARD_SCRIPTSIG_SIZE:
            return (
                f"scriptSig size {len(txin.scriptsig)} exceeds standard limit "
                f"{MAX_STANDARD_SCRIPTSIG_SIZE}"
            )
    for txout in tx.outputs:
        script = txout.scriptpubkey
        if script and script[0] == OP_RETURN:
            if len(script) <= MAX_STANDARD_NULL_DATA_SIZE:
                continue
            return f"OP_RETURN output exceeds standard limit {MAX_STANDARD_NULL_DATA_SIZE}"
        try:
            classify_scriptpubkey(script)
        except (ScriptPubKeyError, IndexError, ValueError):
            return "unrecognized non-standard output script"
    return None
