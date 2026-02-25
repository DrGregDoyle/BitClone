"""
The TxBuilder class, for use in the Wallet

Natural call sequence:
builder = TxBuilder()
builder.set_fee_rate(10)
builder.select_utxos(wallet.address_book, target_amount)
builder.add_output(recipient_address, amount)
builder.add_change_output(wallet)
builder.sign(wallet)
tx = builder.build()
"""

from src.tx.tx import UTXO


class TxBuilder:
    """
    Used by the Wallet to build transactions
    """

    def __init__(self):
        self._inputs: list[UTXO] = []  # UTXOs being spent
        self._outputs: list[tuple[str, int]] = []  # (address, amount) pairs
        self._fee_rate: int = 1  # sat/vbyte
        self._change_address: str | None = None

    def add_input(self, utxo: UTXO):
        # TODO: Add UTXO validation here
        self._inputs.append(utxo)

    def add_output(self, address: str, amount: int):
        # TODO: Validate address
        self._outputs.append((address, amount))

    def set_fee_rate(self, fee_rate: int):
        self._fee_rate = max(1, fee_rate)
