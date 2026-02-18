"""
The Coinbase class, for use in Blocks

Implements BIP34 (block height in coinbase) and BIP141 (witness commitment)
"""
from src.core import CoinbaseError, Serializable, SERIALIZED
from src.script.stack import BitNum
from src.tx.tx import TxOut, TxIn, Witness, Transaction

# --- CONSTANTS --- #
MAX_SCRIPTSIG_BYTES = 100
DEFAULT_SEQUENCE = 0xffffffff
MAX_VOUT = 0xffffffff
COINBASE_MATURITY = 100
WITNESS_RESERVED_VALUE_SIZE = 32
TXID_SIZE = 32

__all__ = ["Coinbase"]


class Coinbase(Serializable):
    """
    Coinbase transaction for block rewards.

    Requirements (per Bitcoin consensus rules):
        - First transaction in every block
        - Single input with txid=0x00*32, vout=0xffffffff
        - ScriptSig must start with block height (BIP34)
        - Total output value ≤ block_reward (subsidy + fees)
        - Locktime typically set to height + 100 (maturity period)
        - For SegWit blocks:
            * Must include witness reserved value (32 zero bytes)
            * Must include witness commitment in an output
    """
    __slots__ = ('tx', 'height', 'block_reward', 'wtxid_commitment')

    def __init__(
            self,
            outputs: list[TxOut],
            height: int,
            block_reward: int,
            custom_scriptsig: bytes = None,
            wtxid_commitment: bytes = None
    ):
        """
        Create a coinbase transaction.

        Args:
            outputs: List of transaction outputs (must include wtxid commitment if segwit)
            height: Block height for BIP34 compliance
            block_reward: Maximum spendable amount (subsidy + fees)
            custom_scriptsig: Optional custom data after height (e.g., miner name)
            wtxid_commitment: Witness commitment scriptPubKey (required for segwit blocks)

        Raises:
            CoinbaseError: If validation fails
        """
        # --- Validation (fail fast) ---

        # 1. Check we have outputs
        if not outputs:
            raise CoinbaseError("Coinbase must have at least one output")

        # 2. Check custom scriptsig size
        if custom_scriptsig and len(custom_scriptsig) > MAX_SCRIPTSIG_BYTES:
            raise CoinbaseError(
                f"Custom scriptsig ({len(custom_scriptsig)} bytes) exceeds "
                f"maximum {MAX_SCRIPTSIG_BYTES} bytes"
            )

        # 3. Validate block reward
        output_total = sum(output.amount for output in outputs)
        if output_total > block_reward:
            subsidy = self.calculate_block_subsidy(height)
            fees = block_reward - subsidy
            raise CoinbaseError(
                f"Output total {output_total:,} sat exceeds block reward {block_reward:,} sat\n"
                f"  Block subsidy: {subsidy:,} sat\n"
                f"  Transaction fees: {fees:,} sat\n"
                f"  Overspend: {output_total - block_reward:,} sat"
            )

        # 4. If segwit, verify wtxid commitment is in an output
        if wtxid_commitment:
            wtxid_found = any(
                wtxid_commitment in output.scriptpubkey
                for output in outputs
            )
            if not wtxid_found:
                raise CoinbaseError(
                    f"Witness commitment {wtxid_commitment.hex()} not found in any "
                    f"output scriptPubKey. For segwit blocks, the commitment must be "
                    f"included in one of the outputs."
                )

        # --- Construction ---

        # Build scriptsig: height (BIP34) + custom data
        height_bytes = self._encode_height(height)
        custom_scriptsig = custom_scriptsig or b''
        coinbase_scriptsig = height_bytes + custom_scriptsig

        # Create coinbase input
        coinbase_txin = TxIn(
            txid=b'\x00' * TXID_SIZE,
            vout=MAX_VOUT,
            scriptsig=coinbase_scriptsig,
            sequence=DEFAULT_SEQUENCE
        )

        # Create witness if segwit (witness reserved value)
        coinbase_witness = None
        if wtxid_commitment:
            witness_reserved_value = b'\x00' * WITNESS_RESERVED_VALUE_SIZE
            coinbase_witness = [Witness(items=[witness_reserved_value])]

        # Create transaction
        self.tx = Transaction(
            inputs=[coinbase_txin],
            outputs=outputs,
            witness=coinbase_witness,
            locktime=height + COINBASE_MATURITY
        )

        # Store metadata
        self.height = height
        self.block_reward = block_reward
        self.wtxid_commitment = wtxid_commitment or b''

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        """
        Deserialize a coinbase transaction from bytes.

        Note: This reconstructs only the transaction structure. Metadata like
        block_reward and wtxid_commitment cannot be reliably extracted from
        serialized bytes alone and will be set to None/defaults.

        To fully reconstruct a Coinbase with metadata, use the constructor.

        Args:
            byte_stream: Serialized transaction bytes

        Returns:
            Coinbase instance with partial metadata
        """
        temp_tx = Transaction.from_bytes(byte_stream)

        # Create new instance bypassing __init__ validation
        obj = object.__new__(cls)
        obj.tx = temp_tx

        # Attempt to extract height from scriptsig (BIP34)
        try:
            scriptsig = temp_tx.inputs[0].scriptsig
            height_len = scriptsig[0]  # First byte is length
            height_bytes = scriptsig[1:1 + height_len]
            obj.height = BitNum.from_bytes(height_bytes).value
        except (IndexError, ValueError, CoinbaseError):
            obj.height = None

        # Metadata that cannot be recovered from bytes
        obj.block_reward = None
        obj.wtxid_commitment = b''

        return obj

    def to_bytes(self) -> bytes:
        """Serialize the coinbase transaction to bytes."""
        return self.tx.to_bytes()

    def to_dict(self) -> dict:
        """
        Return dictionary representation with coinbase-specific metadata.

        Returns:
            Dictionary containing coinbase details and full transaction data
        """
        subsidy = self.calculate_block_subsidy(self.height) if self.height is not None else None
        fees = (self.block_reward - subsidy) if (self.block_reward and subsidy is not None) else None

        return {
            "type": "coinbase",
            "height": self.height,
            "block_reward": self.block_reward,
            "block_subsidy": subsidy,
            "transaction_fees": fees,
            "total_output_value": self.total_output_value,
            "has_witness_commitment": bool(self.wtxid_commitment),
            "wtxid_commitment": self.wtxid_commitment.hex() if self.wtxid_commitment else None,
            "locktime": self.tx.locktime,
            "maturity_height": self.height + COINBASE_MATURITY if self.height is not None else None,
            "transaction": self.tx.to_dict()
        }

    def _encode_height(self, height: int) -> bytes:
        """
        Encode block height as minimally encoded serialized CScript (BIP34).
        """
        height_bytes = BitNum(height).to_bytes()
        return bytes([len(height_bytes)]) + height_bytes

    # --- Properties --- #

    @property
    def txid(self) -> bytes:
        """Get the coinbase transaction ID."""
        return self.tx.txid

    @property
    def wtxid(self) -> bytes:
        """Get the coinbase witness transaction ID."""
        return self.tx.wtxid

    @property
    def outputs(self) -> list[TxOut]:
        """Access coinbase outputs."""
        return self.tx.outputs

    @property
    def total_output_value(self) -> int:
        """Calculate total value of all outputs in satoshis."""
        return sum(output.amount for output in self.tx.outputs)

    @property
    def has_witness(self) -> bool:
        """Check if coinbase has witness data (segwit block)."""
        return bool(self.wtxid_commitment)

    # --- Static Methods --- #

    @staticmethod
    def calculate_block_subsidy(height: int) -> int:
        """
        Calculate block subsidy (coinbase reward) based on height.

        Bitcoin halves the subsidy every 210,000 blocks:
        - Blocks 0-209,999:      50 BTC
        - Blocks 210,000-419,999: 25 BTC
        - Blocks 420,000-629,999: 12.5 BTC
        - ... and so on

        Args:
            height: Block height

        Returns:
            Subsidy in satoshis (1 BTC = 100,000,000 satoshis)
        """
        halvings = height // 210_000

        # After 64 halvings, subsidy becomes zero
        if halvings >= 64:
            return 0

        # Start with 50 BTC (5,000,000,000 satoshis) and halve
        return 5_000_000_000 >> halvings

    @staticmethod
    def calculate_block_reward(height: int, tx_fees: int) -> int:
        """
        Calculate total block reward (subsidy + transaction fees).

        Args:
            height: Block height
            tx_fees: Sum of all transaction fees in the block (satoshis)

        Returns:
            Total block reward in satoshis
        """
        return Coinbase.calculate_block_subsidy(height) + tx_fees


# --- TESTING --- #
if __name__ == "__main__":
    import json

    sep = "=" * 80

    # Test 1: Simple coinbase (no segwit)
    print(sep)
    print("TEST 1: Simple Coinbase (Legacy)")
    print(sep)

    test_height = 700_000
    test_subsidy = Coinbase.calculate_block_subsidy(test_height)
    test_fees = 12_000_000  # 0.12 BTC in fees
    reward = test_subsidy + test_fees

    test_output = TxOut(
        amount=reward,  # Total reward (subsidy + fees)
        scriptpubkey=bytes.fromhex("76a914" + "00" * 20 + "88ac")  # P2PKH
    )

    coinbase = Coinbase(
        outputs=[test_output],
        height=test_height,
        block_reward=reward,
        custom_scriptsig=b'/BitClone/Test/'
    )

    print(f"Block Height: {test_height:,}")
    print(f"Subsidy: {test_subsidy:,} sat ({test_subsidy / 1e8:.8f} BTC)")
    print(f"Fees: {test_fees:,} sat ({test_fees / 1e8:.8f} BTC)")
    print(f"Total Reward: {reward:,} sat ({reward / 1e8:.8f} BTC)")
    print(f"\nTXID: {coinbase.txid[::-1].hex()}")
    print(f"Locktime: {coinbase.tx.locktime:,} (matures at block {test_height + COINBASE_MATURITY:,})")
    print(f"\nCoinbase JSON:")
    print(json.dumps(coinbase.to_dict(), indent=2))

    # Test 2: SegWit coinbase
    print("\n" + sep)
    print("TEST 2: SegWit Coinbase with Witness Commitment")
    print(sep)

    # Create witness commitment output
    commitment = bytes.fromhex("6a24aa21a9ed") + b'\x00' * 32  # OP_RETURN + commitment

    segwit_outputs = [
        TxOut(amount=reward, scriptpubkey=bytes.fromhex("76a914" + "00" * 20 + "88ac")),
        TxOut(amount=0, scriptpubkey=commitment)  # Witness commitment (always 0 value)
    ]

    segwit_coinbase = Coinbase(
        outputs=segwit_outputs,
        height=test_height,
        block_reward=reward,
        custom_scriptsig=b'/BitClone/SegWit/',
        wtxid_commitment=commitment
    )

    print(f"WTXID: {segwit_coinbase.wtxid[::-1].hex()}")
    print(f"Has Witness: {segwit_coinbase.has_witness}")
    print(f"Output Count: {len(segwit_coinbase.outputs)}")
    print(f"Witness Commitment: {segwit_coinbase.wtxid_commitment.hex()}")

    # Test 3: Serialization round-trip
    print("\n" + sep)
    print("TEST 3: Serialization Round-Trip")
    print(sep)

    serialized = coinbase.to_bytes()
    deserialized = Coinbase.from_bytes(serialized)

    print(f"Original Height: {coinbase.height}")
    print(f"Deserialized Height: {deserialized.height}")
    print(f"Serialization matches: {serialized == deserialized.to_bytes()}")

    # Test 4: Different heights
    print("\n" + sep)
    print("TEST 4: Block Subsidy at Different Heights")
    print(sep)

    test_heights = [0, 1, 209_999, 210_000, 420_000, 630_000, 840_000, 13_440_000]
    for h in test_heights:
        sub = Coinbase.calculate_block_subsidy(h)
        btc = sub / 1e8
        print(f"Height {h:>10,}: {sub:>15,} sat ({btc:>10.8f} BTC)")

    print("\n" + sep)
