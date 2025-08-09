"""
Tests for the Node class and related operations
"""
from secrets import token_bytes

from src.node import Node


def test_version():
    random_noise = token_bytes(4)
    usr_agent = random_noise.hex()
    test_node = Node(usr_agent=usr_agent)

    random_version = test_node._build_version("127.0.0.1", 8333)
    recovered_version = test_node.parse_message(random_version.header(), random_version.payload())

    assert random_version.message == recovered_version.message, \
        "create_version function in Node class failed to reconstruct Version message"
