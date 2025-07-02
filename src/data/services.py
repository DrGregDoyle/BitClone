"""
The Enum class for services node types
"""
from enum import Enum


class NodeType(Enum):
    NODE_NETWORK = pow(2, 0)
    NODE_GETUTXO = pow(2, 1)
    NODE_BLOOM = pow(2, 2)
    NODE_WITNESS = pow(2, 3)
    NODE_XTHING = pow(2, 4)
    NODE_COMPACT_FILTERS = pow(2, 6)
    NODE_NETWORK_LIMITED = pow(2, 10)

    def to_bytes(self):
        """
        Returns the little-endian byte representation of the integer
        """
        return self.value.to_bytes(8, "little")


# TESTING
if __name__ == "__main__":
    type1 = NodeType(1)
    print(f"TYPE1 BYTES: {type1.to_bytes().hex()}")
