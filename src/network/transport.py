"""
Methods for sending/receiving messages and connecting to peers
"""
from src.network.message_factory import create_version_msg
from src.network.network_data import NetAddr
from src.network.network_types import Services


def lmab_handshake():
    local_netaddr = NetAddr(
        time=None, services=Services(0), ip_addr="198.84.237.10", port=8333, is_version=True
    )
    remote_netaddr = NetAddr(
        time=None, services=Services(0), ip_addr="127.0.0.1", port=8333, is_version=True
    )

    local_version = create_version_msg(
        protocol_version=70014,
        services=0,
        remote_addr=remote_netaddr,
        local_addr=local_netaddr,
        nonce=0,
        user_agent="/BitClone: 0.0.1/",
        last_block=0
    )
    print(f"LOCAL VERSION: {local_version.to_json()}")


if __name__ == "__main__":
    lmab_handshake()
