"""
The enum class for the type of services
"""
from enum import Enum


class Services(Enum):
    NODE_NETWORK = 0x01
    NODE_GETUTXO = 0x02
    NODE_BLOOM = 0x04
    NODE_WITNESS = 0x08
    NODE_XTHIN = 0x10  # Discontinued
    NODE_COMPACT_FILTERS = 0x40
    NODE_NETWORK_LIMITED = 0x0400
    UNKNOWN = 0x00

    def to_bytes(self):
        return self.value.to_bytes(8, "little")


# TESTING
if __name__ == "__main__":
    test_node = Services(4)
    print(f"TEST NODE: {test_node.name}")
    print(f"NODE BYTES: {test_node.to_bytes().hex()}")
