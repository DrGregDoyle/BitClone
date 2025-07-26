"""
The Node class
"""

from time import time as now

from src.data import NetAddr, BitcoinFormats, Header, NodeType
from src.network.control_messages import *
from src.network.message import Message

LEARN_ME_A_BITCOIN_IP = "162.120.69.182"
BN = BitcoinFormats.Network


class Node:

    def __init__(self):
        pass

    def create_version_message(self, remote_ip: str = LEARN_ME_A_BITCOIN_IP, port: int = 8333):
        current_time = int(now())

        # Create remote addr
        remote_addr = NetAddr(
            timestamp=current_time,
            services=NodeType.NONE,
            ip_addr=remote_ip,
            port=port,
            is_version=True
        )

        # Create local addr
        local_addr = NetAddr(
            timestamp=current_time,
            services=NodeType.NONE,
            ip_addr="127.0.0.1",
            port=port,
            is_version=True
        )

        version_message = Version(
            version=0,
            services=NodeType.NONE,
            timestamp=current_time,
            remote_addr=remote_addr,
            local_addr=local_addr,
            nonce=0,
            user_agent="Dr. Greg | BitClone testing",
            last_block=0
        )
        return version_message

    def parse_message(self, message: bytes) -> Message:
        """
        Reads in the header and returns the correct message based on the command
        """
        # Split header and payload
        header_bytes = message[:BN.MESSAGE_HEADER]
        payload_bytes = message[BN.MESSAGE_HEADER:]

        print(f"HEADER BYTES: {header_bytes.hex()}")
        print(f"PAYLOAD BYTES: {payload_bytes[:50].hex()}{'...' if len(payload_bytes) > 50 else ''}")

        # Parse header
        recovered_header = Header.from_bytes(header_bytes)
        print(f"HEADER: {recovered_header.to_dict()}")

        match recovered_header.command:
            case "version":
                return Version.from_bytes(payload_bytes)
            case _:
                return None


# --- TESTING
if __name__ == "__main__":
    test_node = Node()
    test_version_msg = test_node.create_version_message()
    print(f"VERSION MESSAGE: {test_version_msg.to_json()}")
    print(f"FULL MESSAGE: {test_version_msg.message.hex()}")

    recovered_message = test_node.parse_message(test_version_msg.message)
    print(f"RECOVERED MESSAGE: {recovered_message.to_json()}")
    print(f"MESSAGES AGREE? {test_version_msg.message == recovered_message.message}")
