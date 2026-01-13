"""
Methods for sending/receiving messages and connecting to peers
"""
import socket
import time

from src.network.ctrl_msg import Version, VerAck
from src.network.header import Header
from src.network.message import Message
from src.network.message_factory import create_version_msg
from src.network.network_data import NetAddr
from src.network.network_types import Services

# --- Learn Me A Bitcoin IP
LMAB_IP = "162.120.69.182"
# --- My IP (dynamic)
MY_IP = "198.84.237.10"


def send_message(sock: socket.socket, message: Message) -> None:
    """Send a message to the connected peer"""
    data = message.to_bytes()
    sock.sendall(data)
    print(f"Sent {message.__class__.__name__}: {len(data)} bytes")


def receive_message(sock: socket.socket) -> Message:
    """Receive a message from the connected peer"""
    # First, read the header (24 bytes)
    header_bytes = sock.recv(24)
    if len(header_bytes) < 24:
        raise ConnectionError("Failed to receive complete header")

    # Parse the header to get the payload size

    header = Header.from_bytes(header_bytes)
    print(f"Receiving {header.command}: {header.size} bytes")

    # Read the payload
    payload_bytes = b''
    remaining = header.size
    while remaining > 0:
        chunk = sock.recv(min(remaining, 4096))
        if not chunk:
            raise ConnectionError("Connection closed while receiving payload")
        payload_bytes += chunk
        remaining -= len(chunk)

    # Reconstruct the full message and deserialize
    full_message = header_bytes + payload_bytes
    message_class = Message.get_registered(header.command)

    if message_class:
        return message_class.from_bytes(full_message)
    else:
        raise ValueError(f"Unknown message type: {header.command}")


def open_connection(ip_addr: str, port: int = 8333) -> socket.socket:
    """Open a TCP connection to a Bitcoin node"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)  # 30 second timeout
    try:
        print(f"Connecting to {ip_addr}:{port}...")
        sock.connect((ip_addr, port))
        print("Connected!")
        return sock
    except socket.error as e:
        sock.close()
        raise ConnectionError(f"Failed to connect: {e}")


def perform_handshake(ip_addr: str, port: int = 8333) -> socket.socket:
    """
    Perform a complete Bitcoin handshake:
    1. Connect to peer
    2. Send our version message
    3. Receive their version message
    4. Receive their verack
    5. Send our verack

    Returns the connected socket for further communication
    """
    # Open connection
    sock = open_connection(ip_addr, port)

    try:
        # Create our version message
        local_netaddr = NetAddr(
            time=None,
            services=Services(0),
            ip_addr=MY_IP,
            port=8333,
            is_version=True
        )
        remote_netaddr = NetAddr(
            time=None,
            services=Services(0),
            ip_addr=ip_addr,
            port=port,
            is_version=True
        )

        our_version = create_version_msg(
            protocol_version=70015,
            services=0,
            remote_addr=remote_netaddr,
            local_addr=local_netaddr,
            nonce=int(time.time()),  # Use timestamp as nonce
            user_agent="/BitClone:0.0.1/",
            last_block=0
        )

        # Step 1: Send our version
        print("\n=== Step 1: Sending our version ===")
        send_message(sock, our_version)

        # Step 2: Receive their version
        print("\n=== Step 2: Receiving their version ===")
        their_version = receive_message(sock)
        if not isinstance(their_version, Version):
            raise ValueError(f"Expected Version, got {type(their_version)}")
        print(f"Peer version: {their_version.protocol_version}")
        print(f"Peer user agent: {their_version.user_agent}")
        print(f"Peer version dict: {their_version.to_json()}")

        # Step 3: Receive their verack
        print("\n=== Step 3: Receiving their verack ===")
        their_verack = receive_message(sock)
        if not isinstance(their_verack, VerAck):
            raise ValueError(f"Expected VerAck, got {type(their_verack)}")
        print("Received verack from peer")
        print(f"Peer Verack: {their_verack.to_json()}")

        # Step 4: Send our verack
        print("\n=== Step 4: Sending our verack ===")
        our_verack = VerAck()
        send_message(sock, our_verack)

        print("\n=== Handshake complete! ===")
        return sock

    except Exception as e:
        print(f"Handshake failed: {e}")
        sock.close()
        raise


if __name__ == "__main__":
    perform_handshake(LMAB_IP, 8333)
