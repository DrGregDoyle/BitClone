"""
Methods for parsing raw data
"""


def decode_compact_size(data: str | bytes):
    """
    Decode accepts either hex string or bytes object
    """
    data = data.hex() if isinstance(data, bytes) else data  # Data is now a hex string

    first_byte = int.from_bytes(bytes.fromhex(data[:2]), byteorder="big")
    match first_byte:
        case 0xfd | 0xfe | 0xff:
            l_index = 2
            diff = first_byte - 0xfb
            r_index = 2 + pow(2, diff)
        case _:
            l_index = 0
            r_index = 2
    num = int.from_bytes(bytes.fromhex(data[l_index: r_index]), byteorder="little")
    return num, r_index


def decode_endian(data: str | bytes):
    # Get data as hex string
    data = data.hex() if isinstance(data, bytes) else data

    # reverse data order
    _atad = "".join([data[x:x + 2] for x in reversed(range(0, len(data), 2))])

    # return integer
    return int(_atad, 16)


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
