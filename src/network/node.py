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



