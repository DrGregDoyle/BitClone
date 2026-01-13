"""
Classes for different types of Network data structures
"""
from src.core import Serializable, SERIALIZED, get_stream, read_little_int, read_stream, read_big_int, read_compact_size
from src.data import IP_ADDRESS, parse_ip_address, ip_from_netaddr, netaddr_bytes, ip_display, write_compact_size
from src.network.network_types import Services, InvType
from src.tx.tx import Transaction


class NetAddr(Serializable):
    """
    The standard format of a network address
    -----------------------------------------------------------------
    |   Name            | Data type | Formatted             | Size  |
    -----------------------------------------------------------------
    |   time*           | int       | little-endian         | 4     |
    |   Services        | bytes     | little-endian         | 8     |
    |   ip address      | ipv6      | network byte order    | 16    |
    |   port            | int       | network byte order    | 2     |
    -----------------------------------------------------------------
    *time not present in version message
    """

    def __init__(self, time: int | None, services: Services, ip_addr: IP_ADDRESS | str, port: int,
                 is_version: bool = False):
        self.time = None if is_version else time
        self.services = services
        self.ip_addr = parse_ip_address(ip_addr)
        self.port = port

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED, is_version: bool = False):
        stream = get_stream(byte_stream)

        # Time
        if not is_version:
            time = read_little_int(stream, 4)
        else:
            time = None

        # Services
        service_int = read_little_int(stream, 8)
        services = Services(service_int)

        # IP address
        ip_bytes = read_stream(stream, 16)
        ip_addr = ip_from_netaddr(ip_bytes)

        # port
        port = read_big_int(stream, 2)

        return cls(time, services, ip_addr, port)

    def to_bytes(self) -> bytes:
        parts = [
            self.time.to_bytes(4, "little") if self.time else b'',
            self.services.to_bytes(8, "little"),
            netaddr_bytes(self.ip_addr),
            self.port.to_bytes(2, "big")
        ]
        return b''.join(parts)

    def to_dict(self):
        return {
            "time": self.time if self.time else "",
            "serivces": self.services.name,
            "ip_addr": ip_display(self.ip_addr),
            "port": self.port
        }


class InvVector(Serializable):
    """
    The inventory vector data structure
    """

    def __init__(self, inv_type: int | InvType, obj_hash: bytes):
        # Validation
        if isinstance(inv_type, int):
            # Check if the integer corresponds to a valid InvType value
            valid_values = {member.value for member in InvType}
            if inv_type not in valid_values:
                raise ValueError(f"Invalid inv_type: {inv_type}. Must be one of {sorted(valid_values)}")
            self.type = InvType(inv_type)
        elif isinstance(inv_type, InvType):
            self.type = inv_type
        else:
            raise TypeError(f"inv_type must be int or InvType, got {type(inv_type)}")

        # Validate hash length
        if not isinstance(obj_hash, bytes):
            raise TypeError(f"obj_hash must be bytes, got {type(obj_hash)}")
        if len(obj_hash) != 32:
            raise ValueError(f"obj_hash must be exactly 32 bytes, got {len(obj_hash)}")

        self.hash = obj_hash

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # inv_type = 4 byte little-endian int
        int_type = read_little_int(stream, 4)

        # hash = 32 bytes
        obj_hash = read_stream(stream, 32)

        return cls(int_type, obj_hash)

    def to_bytes(self) -> bytes:
        parts = [
            self.type.to_bytes(4, "little"),
            self.hash
        ]
        return b''.join(parts)

    def to_dict(self) -> dict:
        return {
            "type": self.type.name,
            "hash": self.hash.hex()
        }


class PrefilledTx(Serializable):
    """
     -------------------------------------------------------------
    |   Name    |   Data type   |   byte format |   byte size   |
    -------------------------------------------------------------
    |   Index   |   int         |   CompactSize |   varInt      |
    |   Tx      |   Transaction |   tx.to_bytes |   var         |
    -------------------------------------------------------------
    NB: The index will be differentially encoded since the last PrefilledTx in a list
    """
    __slots__ = ("index", "tx")

    def __init__(self, diff_index: int, tx: Transaction):
        self.index = diff_index
        self.tx = tx

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # Index
        int_index = read_compact_size(stream)

        # tx
        tx = Transaction.from_bytes(stream)

        return cls(int_index, tx)

    def to_bytes(self) -> bytes:
        return write_compact_size(self.index) + self.tx.to_bytes()

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "tx": self.tx.to_dict(),
            "NB": "Index is differentially encoded since the last PrefilledTx in a list"
        }


# --- TESTING
if __name__ == "__main__":
    sep = "===" * 40

    print(" --- NETWORK DATA TESTING --- ")
    print(sep)

    # NetAddr
    test_netaddr_bytes = bytes.fromhex("010000000000000000000000000000000000FFFF0A000001208D")
    test_netaddr = NetAddr.from_bytes(test_netaddr_bytes, is_version=True)
    print(f"TEST NETADDR: {test_netaddr.to_json()}")
    print(sep)

    # InvVector
    test_invvec_bytes = bytes.fromhex("01000000ce0f6c28b5869ff166714da5fe08554c70c731a335ff9702e38b00f81ad348c6")
    test_invvec = InvVector.from_bytes(test_invvec_bytes)
    print(f"TEST INVVECTOR: {test_invvec.to_json()}")
    print(sep)

    # PrefilledTx
    test_tx_bytes = bytes.fromhex(
        "02000000000101a4aadf71fc6951f187680a7cacfcb21aab40570c26a235f7bdf0e48845142e932b00000000ffffffff024365790000000000160014ba96add1ad29d726f9ba5961db67a5abe4888a88ebf20200000000001600147ed35ba6c764b39cc29db73772e76788bbe8039c02483045022100c7ad25debed0fe9412ab0ea26a672f5b8e54992a7b4dec00241444bb18e8c0c302203513d2e655deadcd92326e27824f7f5a9eac5c2a48457536c65e49ebca27373e01210228484fe2b39887c41505947fe0e8c7b637a60e00990fd8f86058d0c3f5639a8000000000")
    test_tx = Transaction.from_bytes(test_tx_bytes)
    test_prefilled_tx = PrefilledTx(0, test_tx)
    print(f"TEST PREFILLED TX: {test_prefilled_tx.to_json()}")
    print(sep)
