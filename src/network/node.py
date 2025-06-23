"""
The Node class for Bitcoin
"""

import socket


def open_socket(ip_address: str, port: int = 8333) -> socket.socket | None:
    try:
        # Create a TCP/IP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Optionally set timeout
        s.settimeout(10)
        # Connect to the node
        s.connect((ip_address, port))
        print(f"Connected to {ip_address}:{port}")
        # You can now use s.send(), s.recv(), etc.
        # Remember to close it when done
        return s  # or store as self.sock for later use

    except Exception as e:
        print(f"Failed to connect to {ip_address}:{port}: {e}")
        return None


def close_socket(s: socket.socket):
    try:
        s.close()
        return True
    except Exception as e:
        print(f"Failed to close socket: {s}")
        return False

# class Node:
#
#     def __init__(self):
#         self.mf = MessageFactory()
#
#
# if __name__ == "__main__":
#     remote_ip = "162.120.69.182"
#     mf = MessageFactory()
#     with open_socket(remote_ip) as test_sock:
#         my_version_payload = mf.get_version_payload(remote_ip)
#         my_version_header = mf.get_header_from_payload(my_version_payload.to_bytes(), "version")
#         my_version = my_version_header.to_bytes() + my_version_payload.to_bytes()
#     close_socket(test_sock)
