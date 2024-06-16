"""
A file for testing the Stack class
"""
from random import randint

from src.script import Stack


def test_stack():
    """
    We test basic push/pop capabilities of the stack
    """
    element1 = randint(1, 100)
    element2 = randint(1, 100)
    element3 = randint(1, 100)

    in_test_stack = Stack()
    in_test_stack.push(element1)
    in_test_stack.push(element2)
    in_test_stack.push(element3)

    assert in_test_stack.pop() == element3
    assert in_test_stack.pop() == element2
    assert in_test_stack.pop() == element1
    assert in_test_stack.pop() is None
