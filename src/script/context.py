"""Typed validation inputs used by the script interpreter."""
from __future__ import annotations

import json
from dataclasses import dataclass, replace
from enum import Enum
from typing import Optional

from src.core.chainparams import ScriptVerifyFlag

__all__ = [
    "ExecutionContext",
    "LegacyExecutionContext",
    "ScriptExecutionContext",
    "ScriptValidationInput",
    "SignatureVersion",
]


class SignatureVersion(str, Enum):
    BASE = "base"
    WITNESS_V0 = "witness_v0"
    TAPROOT = "taproot"
    TAPSCRIPT = "tapscript"


@dataclass(frozen=True, slots=True)
class ScriptValidationInput:
    """The immutable transaction data needed to validate one input."""

    tx: 'Tx'
    input_index: int
    spent_outputs: tuple['UTXO', ...]
    flags: ScriptVerifyFlag

    def __post_init__(self) -> None:
        if self.input_index < 0 or self.input_index >= len(self.tx.inputs):
            raise ValueError("Script input index is outside the transaction inputs")
        if len(self.spent_outputs) != len(self.tx.inputs):
            raise ValueError("Script validation requires one spent output per transaction input")

    @property
    def spent_output(self) -> 'UTXO':
        return self.spent_outputs[self.input_index]

    def execution_context(
            self,
            *,
            script_code: bytes | None = None,
            signature_version: SignatureVersion = SignatureVersion.BASE,
            tapleaf_hash: bytes | None = None,
    ) -> 'ScriptExecutionContext':
        return ScriptExecutionContext(
            validation=self,
            script_code=script_code,
            signature_version=signature_version,
            tapleaf_hash=tapleaf_hash,
        )


@dataclass(frozen=True, slots=True)
class ScriptExecutionContext:
    """Interpreter state derived from a validated transaction input."""

    validation: ScriptValidationInput
    script_code: bytes | None = None
    signature_version: SignatureVersion = SignatureVersion.BASE
    tapleaf_hash: bytes | None = None

    @property
    def tx(self):
        return self.validation.tx

    @property
    def input_index(self) -> int:
        return self.validation.input_index

    @property
    def utxos(self) -> list['UTXO']:
        return list(self.validation.spent_outputs)

    @property
    def utxo(self):
        return self.validation.spent_output

    @property
    def script_flags(self) -> ScriptVerifyFlag:
        return self.validation.flags

    @property
    def is_segwit(self) -> bool:
        return self.signature_version in {
            SignatureVersion.WITNESS_V0,
            SignatureVersion.TAPROOT,
            SignatureVersion.TAPSCRIPT,
        }

    @property
    def tapscript(self) -> bool:
        return self.signature_version is SignatureVersion.TAPSCRIPT

    @property
    def merkle_root(self) -> bytes | None:
        """Compatibility alias for the old, ambiguously named field."""
        return self.tapleaf_hash

    def with_script_code(self, script_code: bytes) -> 'ScriptExecutionContext':
        return replace(self, script_code=script_code)

    def with_signature_version(
            self,
            signature_version: SignatureVersion,
            *,
            tapleaf_hash: bytes | None = None,
    ) -> 'ScriptExecutionContext':
        return replace(
            self,
            signature_version=signature_version,
            tapleaf_hash=tapleaf_hash,
        )


@dataclass(frozen=True)
class LegacyExecutionContext:
    """
    Compatibility adapter for older direct ScriptEngine callers.

    Consensus transaction validation uses ``ScriptValidationInput`` and
    ``ScriptExecutionContext`` so required data can no longer be omitted.
    """
    tx: Optional['Tx'] = None
    input_index: Optional[int] = None
    utxos: Optional[list['UTXO']] = None
    script_code: Optional[bytes] = None  # For P2SH/witness
    tapscript: bool = False
    is_segwit: bool = False
    merkle_root: Optional[bytes] = None
    # Standalone script-engine callers retain the historical "all supported
    # consensus rules active" behavior. Chain validation always supplies the
    # exact network/height-specific value.
    script_flags: ScriptVerifyFlag | int = (
        ScriptVerifyFlag.P2SH
        | ScriptVerifyFlag.DERSIG
        | ScriptVerifyFlag.CHECKLOCKTIMEVERIFY
        | ScriptVerifyFlag.WITNESS
        | ScriptVerifyFlag.TAPROOT
    )

    def with_script_code(self, script_code: bytes) -> 'LegacyExecutionContext':
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
            "script_flags": self.script_flags,
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


# Compatibility import for existing labs and direct interpreter callers.
ExecutionContext = LegacyExecutionContext
