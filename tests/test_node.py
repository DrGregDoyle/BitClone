"""
Tests for the Node class and related operations
"""
from secrets import token_bytes

from src.node import Node, create_version


def test_version():
    test_node = Node()
    random_noise = token_bytes(4)
    usr_agent = random_noise.hex()
    random_version = create_version(usr_agent=usr_agent)
    recovered_version = test_node.parse_message(random_version.header(), random_version.payload())

    assert random_version.message == recovered_version.message, \
        "create_version function in Node class failed to reconstruct Version message"
