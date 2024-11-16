"""
Methods for parsing raw data
"""


def reverse_bytes(data: str | bytes) -> str:
    data = data.hex() if isinstance(data, bytes) else data
    return "".join([data[x:x + 2] for x in reversed(range(0, len(data), 2))])


def bits_to_target(data: str | bytes) -> str:
    # Get hex string
    data = data.hex() if isinstance(data, bytes) else data

    # Parse
    exp = int(data[:2], 16)  # 1 byte
    coeff = int(data[2:8], 16)  # 3 bytes

    # Calc target
    t_exp = 8 * (exp - 3)
    target = coeff * pow(2, t_exp)

    # Return formatted target | 32 bytes
    return target.to_bytes(length=32, byteorder="big").hex()


def target_to_bits(data: str | bytes) -> str:
    # Get data as hex string
    data = data.hex() if isinstance(data, bytes) else data

    # Get first significant byte
    sig_byte = 0
    while True:
        temp_data = data[2 * sig_byte: 2 * (sig_byte + 1)]
        if temp_data != "00":
            break
        sig_byte += 1

    # Get exp and coefficient
    _exp = format(32 - sig_byte, "02x")
    _coeff = data[2 * sig_byte:2 * (sig_byte + 3)]

    # Return hex string
    return _exp + _coeff


def compress_point(pt: tuple) -> str:
    """
    Given a public key point, we return a 33-byte compressed public key.
    """
    x, y = pt
    parity = "02" if y % 2 == 0 else "03"
    return parity + format(x, "064x")


def decompress_point(data: str) -> tuple | bool:
    parity = 0 if data[:2] == "02" else 1
    _x = int(data[2:66], 16)  # 32 bytes
    from src.backup.library.ecc import SECP256K1
    curve = SECP256K1()
    valid_x = curve.is_x_on_curve(_x)
    if not valid_x:
        return False
    y1 = curve.get_y_from_x(_x)
    y2 = (curve.ORDER - y1) % curve.ORDER
    _y = y1 if y1 % 2 == parity else y2
    return _x, _y
