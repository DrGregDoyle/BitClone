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
