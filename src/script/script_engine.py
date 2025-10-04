"""
The ScriptEngine class
"""

from src.script.stack import BitStack


class ScriptContext:
    """
    Data class for holding elements necessary for script evaluation
    """
    pass


class ScriptEngine:

    def __init__(self):
        self.stack = BitStack()
        self.alt_stack = BitStack()
