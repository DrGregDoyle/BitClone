"""
Methods for connecting to a peer Node
"""

from ipaddress import IPv4Address, IPv6Address
from socket import socket, AF_INET, AF_INET6, SOCK_STREAM
from typing import Union

IP_ADDRESS = Union[IPv4Address, IPv6Address]
LMAB_IP = IPv4Address("162.120.69.182")


def open_connection(ip_addr: IP_ADDRESS, port: int = 8333) -> socket:
    """
    Will open a socket connection to the given ip address at the specified port
    """
    # Determine address family based on IP version
    family = AF_INET6 if isinstance(ip_addr, IPv6Address) else AF_INET

    # Create socket
    sock = socket(family, SOCK_STREAM)

    # Connect to the address (convert IPv4Address/IPv6Address to string)
    sock.connect((str(ip_addr), port))

    return sock
