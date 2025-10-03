"""
Methods for converting between bits and target.
Bits is 4-byte representation of 32-byte target
"""
from src.core import DATA, TargetBitsError

__all__ = ["bits_to_target", "target_to_bits"]


def bits_to_target(target_bits: bytes) -> bytes:
    # --- Validation --- #
    if len(target_bits) != DATA.BITS:
        raise TargetBitsError("Given target bits not of correct length")

    # --- Execution --- #
    exp = target_bits[0]
    coeff = int.from_bytes(target_bits[1:4], 'big')

    target_int = coeff * pow(2, 8 * (exp - 3))

    # Convert to 32 bytes, big-endian
    return target_int.to_bytes(32, 'big')


def target_to_bits(target: bytes) -> bytes:
    # --- Validation --- #
    if len(target) != DATA.TARGET:
        raise TargetBitsError("Given target not of correct length")

    # --- Execution --- #
    # Find the first significant byte
    first_nonzero = next((i for i, b in enumerate(target) if b != 0), len(target))

    # Compute exponent (Bitcoin defines this as 32 - index)
    exp = (32 - first_nonzero).to_bytes(1, "big")

    # Extract first 3 significant bytes
    sig_dig = target[first_nonzero:first_nonzero + 3]

    # If the coefficient has fewer than 3 bytes, pad with zeros
    coeff = sig_dig.ljust(3, b'\x00')

    # If the first byte of the coefficient is >= 0x80, prepend `00` and increase exponent
    if coeff[0] >= 0x80:
        coeff = b'\x00' + coeff[:2]  # Shift the coefficient
        exp = (int.from_bytes(exp, "big") + 1).to_bytes(1, "big")  # Increment exponent

    return exp + coeff
