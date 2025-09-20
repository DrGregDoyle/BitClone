"""
The classes for BitClone transactions
"""
from src.core import Serializable, SERIALIZED, get_stream, read_little_int, read_stream, TX
from src.data import read_compact_size, write_compact_size

__all__ = ["TxInput", "TxOutput", "Witness"]


class TxInput(Serializable):
    """
    TxInput
    -------------------------------------------------------------
    |   Field           |   Byte Size   |   Format              |
    -------------------------------------------------------------
    |   txid            |   32          |   natural byte order  |
    |   vout            |   4           |   little-endian       |
    |   scriptsig_size  |   var         |   CompactSize         |
    |   scriptsig       |   var         |   Script              |
    |   sequence        |   4           |   little-endian       |
    -------------------------------------------------------------
    """
    __slots__ = ("txid", "vout", "scriptsig", "sequence")

    def __init__(self, txid: bytes, vout: int | bytes, scriptsig: bytes, sequence: int | bytes):
        self.txid = txid
        self.vout = vout if isinstance(vout, int) else int.from_bytes(vout, "little")
        self.scriptsig = scriptsig
        self.sequence = sequence if isinstance(sequence, int) else int.from_bytes(sequence, "little")

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        txid = read_stream(stream, TX.TXID, "txid")
        vout = read_little_int(stream, TX.VOUT, "vout")
        scriptsig_size = read_compact_size(stream)
        scriptsig = read_stream(stream, scriptsig_size, "scriptsig")
        sequence = read_little_int(stream, TX.SEQUENCE, "sequence")

        return cls(txid, vout, scriptsig, sequence)

    def to_bytes(self) -> bytes:
        """
        Serialize input
        txid || vout || scriptsig_size || scriptsig || sequence
        """
        parts = [
            self.txid,
            self.vout.to_bytes(TX.VOUT, "little"),
            write_compact_size(len(self.scriptsig)),
            self.scriptsig,
            self.sequence.to_bytes(TX.SEQUENCE, "little")
        ]
        return b''.join(parts)

    def to_dict(self) -> dict:
        return {
            "txid": self.txid.hex(),
            "vout": self.vout,
            "scriptsig_size": len(self.scriptsig),
            "scriptsig": self.scriptsig.hex(),
            "sequence": self.sequence
        }


class TxOutput(Serializable):
    """
    TxInput
    -----------------------------------------------------------------
    |   Field               |   Byte Size   |   Format              |
    -----------------------------------------------------------------
    |   Amount              |   8           |   little-endian       |
    |   scriptpubkey_size   |   var         |   CompactSize         |
    |   scriptpubkey        |   var         |   Script              |
    -----------------------------------------------------------------
    """
    __slots__ = ("amount", "scriptpubkey")

    def __init__(self, amount: int | bytes, scriptpubkey: bytes):
        self.amount = amount if isinstance(amount, int) else int.from_bytes(amount, "little")
        self.scriptpubkey = scriptpubkey

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        amount = read_little_int(stream, TX.AMOUNT, "amount")
        scriptpubkey_size = read_compact_size(stream)
        scriptpubkey = read_stream(stream, scriptpubkey_size, "scriptpubkey")

        return cls(amount, scriptpubkey)

    def to_bytes(self) -> bytes:
        """
        Serializt the TxOutput
        amount || scriptpubkey_size || scriptpubkey
        """
        parts = [
            self.amount.to_bytes(TX.AMOUNT, "little"),
            write_compact_size(len(self.scriptpubkey)),
            self.scriptpubkey
        ]
        return b''.join(parts)

    def to_dict(self) -> dict:
        return {
            "amount": self.amount,
            "scriptpubkey_size": len(self.scriptpubkey),
            "scriptpubkey": self.scriptpubkey.hex()
        }


class Witness(Serializable):
    """
    Witness
    -------------------------------------------------------------
    |   Field           |   Byte Size   |   Format              |
    -------------------------------------------------------------
    |   Stack Items     |   var         |   CompactSize         |
    =============================================================
    |   Size            |   var         |   CompactSize         |
    |   Item            |   var         |   bytes               |
    =============================================================
    |   the Size | Item format repeats for all witness items    |
    -------------------------------------------------------------    
    """
    __slots__ = ("witness_items",)

    def __init__(self, witness_items: list | bytes):
        self.witness_items = witness_items if isinstance(witness_items, list) else [witness_items]

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # Number of stack items
        stack_items = read_compact_size(stream)

        # Get items
        witness_items = []
        for _ in range(stack_items):
            item_len = read_compact_size(stream)
            witness_items.append(read_stream(stream, item_len, "Witness item"))
        return cls(witness_items)

    def to_bytes(self) -> bytes:
        """
        Serialize the stack items
        """
        parts = [write_compact_size(len(self.witness_items))]
        for item in self.witness_items:
            parts.append(write_compact_size(len(item)))
            parts.append(item)
        return b''.join(parts)

    def to_dict(self) -> dict:
        witness_dict = {
            "stack_items": len(self.witness_items)
        }
        for x in range(len(self.witness_items)):
            temp_item = self.witness_items[x]
            witness_dict.update({
                x: {
                    "size": len(temp_item),
                    "item": temp_item.hex()
                }
            })
        return witness_dict


class Transaction(Serializable):
    """
    Transaction
    -------------------------------------------------------------
    |   Field           |   Byte Size   |   Format              |
    -------------------------------------------------------------
    |   Version         |   4           |   little-endian       |
    |   Marker*         |   1           |   fixed byte          |
    |   Flag*           |   1           |   fixed byte          |
    |   input_count     |   var         |   ComapctSize         |
    |   inputs          |   var         |   TxInput             |
    |   output_count    |   var         |   CompactSize         |
    |   outputs         |   var         |   TxOutput            |
    |   witness*        |   var         |   Witness             |
    |   locktime        |   4           |   little-endian       |
    -------------------------------------------------------------
    * indicates optional segwit specific fields
    """
    pass
    # def __init__(self, inputs: list = [], outputs: list = [], witness_list: list = [], version: int | bytes,
    #              locktime: int | bytes):


# -- TESTING ---
if __name__ == "__main__":
    known_witness = bytes.fromhex(
        "024730440220537f470c1a18dc1a9d233c0b6af1d2ce18a07f3b244e4d9d54e0e60c34c55e67022058169cd11ac42374cda217d6e28143abd0e79549f7b84acc6542817466dc9b3001210301c1768b48843933bd7f0e8782716e8439fc44723d3745feefde2d57b761f503")
    test_witness = Witness.from_bytes(known_witness)
    print(f"TEST WITNESS: {test_witness.to_json()}")
