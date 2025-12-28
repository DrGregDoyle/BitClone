"""
Contains the core elements that are used within BitClone

Core:
    -Provides the standard protocol for BitClone elements
    -Provides the reference formats for BitClone formatting
    -Provides custom exceptions for various BitClone elements
"""
# core/__init__.py
from src.core.byte_stream import *
from src.core.exceptions import *
from src.core.formats import *
from src.core.opcodes import *
from src.core.serializable import *
