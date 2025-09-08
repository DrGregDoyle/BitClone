"""
Helper functions for bit manipulation
"""


# --- k Bits from Bytes --- #
def first_bits(digest: bytes, k: int) -> int:
    """
    Get the integer obtained for the first k bits of a given byte digest.
    """
    if k == 0:
        return 0
    d_int = int.from_bytes(digest, "big")
    d_bits = len(digest) * 8
    # shift right to discard the lower (d_bits - k) bits; keeps the top k bits
    return d_int >> (d_bits - k)


# --- TESTING --- #

if __name__ == "__main__":
    known_bytes = bytes.fromhex("00f0")
