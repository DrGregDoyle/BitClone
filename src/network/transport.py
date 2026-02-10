"""
Methods for sending/receiving messages and connecting to peers
"""
import socket
import time
from random import randint

from src.core import NetworkError
from src.data.ip_utils import IP_ADDRESS
from src.network.datatypes.network_data import NetAddr
from src.network.datatypes.network_types import Services
from src.network.messages.ctrl_msg import *
from src.network.messages.data_msg import *  # noqa: F401
from src.network.messages.header import Header
from src.network.messages.message import Message

# --- Learn Me A Bitcoin IP
LMAB_IP = "162.120.69.182"
# --- My IP (dynamic)
MY_IP = "198.84.237.10"
DEFAULT_PORT = 8333

sep1 = "---" * 60
sep2 = "===" * 60


def open_connection(ip_addr: str, port: int = DEFAULT_PORT, timeout: int = 120) -> socket.socket:
    """Open a TCP connection to a Bitcoin node"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)  # 120 second default timeout
    try:
        print(f"Connecting to {ip_addr}:{port}...")
        sock.connect((ip_addr, port))
        print("Connected!")
        return sock
    except socket.error as e:
        sock.close()
        raise ConnectionError(f"Failed to connect: {e}")


def send_message(sock: socket.socket, message: Message) -> None:
    """Send a message to the connected peer"""
    data = message.to_bytes()
    sock.sendall(data)
    print(f"Sent {message.__class__.__name__}: {len(data)} bytes")


def receive_message(sock: socket.socket, command: str = None) -> Message:
    """Receive a message from the connected peer"""
    # Read exactly 24 bytes for header (loop until we get all of them)
    header_bytes = b''
    while len(header_bytes) < 24:
        chunk = sock.recv(24 - len(header_bytes))
        if not chunk:
            raise ConnectionError("Connection closed while receiving header")
        header_bytes += chunk

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

    # (Optional) Validation
    if command and command != header.command:
        raise NetworkError(f"Received message command {header.command} didn't match expected command: {command}")

    if message_class:
        return message_class.from_bytes(full_message)
    else:
        raise ValueError(f"Unknown message type: {header.command}")


class Connector:
    """
    The class used for connecting to a Bitcoin node
    """

    def __init__(self, local_version: int, local_services: int | Services, local_ip: str | IP_ADDRESS,
                 last_block: int, local_port: int = DEFAULT_PORT, local_user_agent: str = "/BitClone:0.0.1/"):
        """
        Constructed using information about the local node. These values will be used later in the handshake.
        """
        self.protocol_version = local_version
        self.services = local_services if isinstance(local_services, int) else Services(local_services)
        self.ip_addr = local_ip
        self.port = local_port
        self.user_agent = local_user_agent
        self.last_block = last_block

    def create_version_message(self, remote_ip: str | IP_ADDRESS, remote_port: int = DEFAULT_PORT,
                               remote_services: int | Services = 0x00, nonce: int = 0) -> Version:
        remote_services = remote_services if isinstance(remote_services, int) else Services(remote_services)
        remote_addr = NetAddr(
            time=None,
            services=remote_services,
            ip_addr=remote_ip,
            port=remote_port,
            is_version=True
        )
        local_addr = NetAddr(
            time=None,
            services=self.services,
            ip_addr=self.ip_addr,
            port=self.port,
            is_version=True
        )
        timestamp = int(time.time())
        nonce = randint(0x00, 0xffffffffffffffff) if nonce == 0 else nonce
        return Version(
            version=self.protocol_version,
            services=self.services,
            timestamp=timestamp,
            remote_addr=remote_addr,
            local_addr=local_addr,
            nonce=nonce,
            user_agent=self.user_agent,
            last_block=self.last_block,
        )

    def handshake(self, sock: socket.socket, peer_ip: str | IP_ADDRESS, peer_port: int = DEFAULT_PORT) -> Message:
        """
        We look to establish a handshake with the given peer. If successful, we return the peer's version message
        """
        # --- Create local version message
        local_version = self.create_version_message(peer_ip, peer_port)

        # --- 1. Send Version message
        send_message(sock, local_version)

        # --- 2. Receive Version message
        remote_version = receive_message(sock, "version")

        # --- 3. Receive VerAck message
        _ = receive_message(sock, "verack")

        # --- 4. Send Verack
        send_message(sock, VerAck())

        return remote_version

    def connect_to_peer(self, peer_ip: str | IP_ADDRESS, peer_port: int = DEFAULT_PORT) -> None:
        """
        We create a loop so that after connecting to peer and a successful handshake, we continue to receive messages from the peer.
        """
        peer_sock = None

        try:
            # 1. Open connection to peer
            peer_sock = open_connection(peer_ip, peer_port)

            # 2. Establish handshake
            remote_version = self.handshake(peer_sock, peer_ip, peer_port)

            # --- LOGGING --- #
            print(f" --- HANDSHAKE COMPLETED SUCCESSFULLY ---")
            print(sep1)
            print(f"Remote Version: {remote_version.to_json(False)}")
            print(sep2)

            # 3. Request peer addresses for more traffic
            send_message(peer_sock, GetAddr())
            peer_sock.settimeout(300)  # Set a longer timeout for idle periods | 5 minutes

            # 4. Loop until interrupt or error
            msg_count = 0
            while True:
                try:
                    message = receive_message(peer_sock)
                    msg_count += 1
                    msg_type = message.__class__.__name__

                    # --- LOGGING --- #
                    print(" --- New Message --- ")
                    print(sep1)
                    print(f"Message Type: {msg_type}")
                    print(f"Message Count: {msg_count}")
                    print(sep2)
                    # print(f"Message dict: {message.to_json(False)}")
                    print(sep2, end="\n\n")

                    if message.header.command == 'ping':
                        encoded_nonce = message.payload
                        my_pong = Pong(int.from_bytes(encoded_nonce, 'little'))
                        send_message(peer_sock, my_pong)
                        print(f" --- PONG --- ")
                        print(sep1)
                        print(f"Send pong message: {my_pong.to_json(False)}")
                        print(sep2)

                except socket.timeout:
                    print(f"[{time.strftime('%H:%M:%S')}] No messages received - connection still alive, waiting...")
                    continue

        except KeyboardInterrupt:
            print("\n\nKeyboard interrupt received. Closing connection...")

        except ConnectionError as e:
            print(f"\nConnection error: {e}")

        except NetworkError as e:
            print(f"\nNetwork error during handshake: {e}")

        except Exception as e:
            print(f"\nUnexpected error: {e}")

        finally:
            if peer_sock:
                peer_sock.close()
                print("Connection closed.")


# --- TESTING --- #
if __name__ == "__main__":
    lmab_connector = Connector(
        local_version=70014,
        local_services=0x00,
        local_ip=MY_IP,
        last_block=0
    )
    lmab_connector.connect_to_peer(LMAB_IP)
