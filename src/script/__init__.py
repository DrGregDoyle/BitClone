"""
script folder used to house all files dealing with Bitcoin Script language and execution
"""
# script/__init__.py
from src.script.op_codes import OPCODES
from src.script.script import ScriptEngine
from src.script.stack import BTCStack, BTCNum
