"""Bitcoin P2P message classes and deterministic built-in registration."""

from src.network.messages.message import Message, UnknownMessage

# Message subclasses register themselves when their modules are imported. Keep
# these imports explicit so command recognition never depends on import order.
from src.network.messages import cf_msg as _cf_msg
from src.network.messages import ctrl_msg as _ctrl_msg
from src.network.messages import data_msg as _data_msg

__all__ = ["Message", "UnknownMessage"]
