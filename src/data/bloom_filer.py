"""
The BloomFilter class
"""


class BloomFilter:
    BYTES_MAX = 36000
    FUNCS_MAX = 50

    def __init__(self):
        self.nFlags = 0
