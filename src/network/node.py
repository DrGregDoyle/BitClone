# """
# The Node class
# """
#
# import socket
# from time import time as now
#
# from src.data import NetAddr, BitcoinFormats, Header, NodeType
# from src.logger import get_logger
# from src.network.control_messages import *
# from src.network.message import Message
#
# LEARN_ME_A_BITCOIN_IP = "162.120.69.182"
# BN = BitcoinFormats.Network
# MB = BitcoinFormats.MagicBytes
#
# __all__ = ["Node"]
# logger = get_logger(__name__)
#
#
# class Node:
#     SOCKET_TIMEOUT = 5
#
#     def __init__(self):
#         pass
#
#     def create_version(self, remote_ip: str = LEARN_ME_A_BITCOIN_IP, port: int = 8333,
#                        usr_agent: str = "Dr. Greg | BitClone testing") -> Version:
#         current_time = int(now())
#
#         # Create remote addr
#         remote_addr = NetAddr(
#             timestamp=current_time,
#             services=NodeType.NONE,
#             ip_addr=remote_ip,
#             port=port,
#             is_version=True
#         )
#
#         # Create local addr
#         local_addr = NetAddr(
#             timestamp=current_time,
#             services=NodeType.NONE,
#             ip_addr="127.0.0.1",
#             port=port,
#             is_version=True
#         )
#
#         version_message = Version(
#             version=0,
#             services=NodeType.NONE,
#             timestamp=current_time,
#             remote_addr=remote_addr,
#             local_addr=local_addr,
#             nonce=0,
#             user_agent=usr_agent,
#             last_block=0
#         )
#         return version_message
#
#     def parse_message(self, message: bytes) -> Message:
#         """
#         Reads in the header and returns the correct message based on the command
#         """
#         # Split header and payload
#         header_bytes = message[:BN.MESSAGE_HEADER]
#         payload_bytes = message[BN.MESSAGE_HEADER:]
#
#         # Parse header
#         recovered_header = Header.from_bytes(header_bytes)
#
#         match recovered_header.command:
#             case "version":
#                 return Version.from_bytes(payload_bytes)
#             case "verack":
#                 if payload_bytes > 0:
#                     raise ValueError("Verack Message has non-empty payload")
#                 return VerAck()
#             # TODO: Add other message types
#             case _:
#                 pass
#                 # return None
#
#     def send_message(self, sock: socket.socket, msg: Message):
#         sock.send(msg.message)
#
#     def recv_message(self, sock: socket.socket):
#         # Read header
#         header = self._recv_header(sock)
#
#         # Read payload
#         payload = sock.recv(header.size)
#         return self.parse_message(header.to_bytes() + payload)
#
#     def _recv_header(self, sock: socket.socket) -> Header:
#         magic_bytes = sock.recv(BN.MAGIC_BYTES)
#         command = sock.recv(BN.COMMAND)
#         size = sock.recv(BN.HEADER_SIZE)
#         checksum = sock.recv(BN.HEADER_CHECKSUM)
#         return Header.from_bytes(magic_bytes + command + size + checksum)
#
#     def handshake(self, remote_ip: str = LEARN_ME_A_BITCOIN_IP, port: int = 8333) -> socket.socket | None:
#         """
#         Bitcoin handshake:
#
#         1. Send our Version
#         2. Receive peer Version
#         3. Receive peer VerAck
#         4. Send our VerAck
#
#         Returns a connected socket on success; otherwise ``None``.
#         """
#
#         sock = self.open_connection(remote_ip, port)
#         if sock is None:
#             logger.error("Could not open connection to %s:%d", remote_ip, port)
#             return None
#
#         try:
#             # 1 ▸ send our Version
#             version_msg = self.create_version(remote_ip=remote_ip, port=port, usr_agent="BitClone/0.1")
#             self.send_message(sock, version_msg)
#
#             # 2 ▸ receive peer Version
#             peer_version = self.recv_message(sock)
#             if not isinstance(peer_version, Version):
#                 raise ValueError(f"Expected Version, got {type(peer_version).__name__}")
#
#             # 3 ▸ receive peer VerAck
#             peer_verack = self.recv_message(sock)
#             if not isinstance(peer_verack, VerAck):
#                 raise ValueError(f"Expected VerAck, got {type(peer_verack).__name__}")
#
#             # 4 ▸ send our VerAck
#             self.send_message(sock, VerAck())
#
#             logger.info("Handshake with %s:%d succeeded.", remote_ip, port)
#             return sock
#
#         except Exception as exc:
#             logger.error("Handshake with %s:%d failed: %s", remote_ip, port, exc)
#             self.close_connection(sock)
#             return None
#
#     def open_connection(self, remote_ip: str = LEARN_ME_A_BITCOIN_IP, port: int = 8333) -> socket.socket:
#         s = None
#         try:
#             s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             s.settimeout(self.SOCKET_TIMEOUT)
#             s.connect((remote_ip, port))
#         except (socket.timeout, OSError) as e:
#             logger.debug(f"Connection attempt to {remote_ip}:{port} failed: {e}")
#             try:
#                 s.close()
#             except (socket.timeout, OSError) as f:
#                 logger.debug(f"Closing socket failed: {f}")
#                 pass  # ignore errors while closing
#         return s
#
#     def close_connection(self, sock: socket.socket):
#         try:
#             sock.shutdown(socket.SHUT_RDWR)  # Disable further sends/receives
#         except OSError as exc:
#             logger.debug("Socket shutdown error: %s", exc)
#
#         try:
#             sock.close()
#             logger.debug("Socket closed.")
#         except Exception as exc:  # pragma: no cover
#             logger.error("Failed to close socket cleanly: %s", exc)
#
#
# # --- TESTING --- #
#
# if __name__ == "__main__":
#     node = Node()
#     peer_sock = node.handshake()  # default IP/port
#     if peer_sock:
#         print("Connected! Ready to send further messages.")
#         node.close_connection(peer_sock)
