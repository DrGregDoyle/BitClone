"""
A library for common encoding functions
"""


def encode_compact_size(n: int) -> str:
    """
    We return a variable length integer in hex such that the first byte indicates the length
    """
    if 0 <= n <= 0xFC:
        return format(n, f"02x")
    elif 0xFD <= n <= 0xFFFF:
        return "fd" + format(n, f"04x")
    elif 0X10000 <= n <= 0xFFFFFFFF:
        return "fe" + format(n, f"08x")
    elif 0x100000000 <= n <= 0xffffffffffffffff:
        return "ff" + format(n, f"016x")
