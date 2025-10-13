"""
Tests for the script engine
"""
# from src.script import ExecutionContext, P2PK_Sig, P2PK_Key, ScriptEngine
from src.script.context import ExecutionContext
from src.script.script_engine import ScriptEngine
from src.script.scriptpubkey import P2PK_Key
from src.script.scriptsig import P2PK_Sig
from src.tx import Transaction, UTXO

# --- HEX Strings for Known elements

p2pk_tx = \
    "01000000019d7a3553c3faec3d88d18b36ec3bfcdf00c7639ea161205a02e7fc9a1a25b61d0100000049483045022100c219a522e65ca8500ebe05a70d5a49d840ccc15f2afa4ee9df783f06b2a322310220489a46c37feb33f52c586da25c70113b8eea41216440eb84771cb67a67fdb68c01ffffffff0200f2052a010000001976a914e32acf8e6718a32029dc395cca1e0ac45c33f14188ac00c817a8040000004341049464205950188c29d377eebca6535e0f3699ce4069ecd77ffebfbd0bcf95e3c134cb7d2742d800a12df41413a09ef87a80516353a2f0a280547bb5512dc03da8ac00000000"
utxo_display_txid = "1db6251a9afce7025a2061a19e63c700dffc3bec368bd1883decfac353357a9d"
utxo_scriptpubkey = \
    "41049464205950188c29d377eebca6535e0f3699ce4069ecd77ffebfbd0bcf95e3c134cb7d2742d800a12df41413a09ef87a80516353a2f0a280547bb5512dc03da8ac"
p2pk_key = \
    "41049464205950188c29d377eebca6535e0f3699ce4069ecd77ffebfbd0bcf95e3c134cb7d2742d800a12df41413a09ef87a80516353a2f0a280547bb5512dc03da8ac"
p2pk_sig = \
    "483045022100c219a522e65ca8500ebe05a70d5a49d840ccc15f2afa4ee9df783f06b2a322310220489a46c37feb33f52c586da25c70113b8eea41216440eb84771cb67a67fdb68c01"


def test_p2pk_pair():
    """
    We validate a known P2PK pair of ScriptPubKey | ScriptSig
    """
    # Setup
    test_tx = Transaction.from_bytes(bytes.fromhex(p2pk_tx))
    test_utxo = UTXO(
        txid=bytes.fromhex(utxo_display_txid)[::-1],  # Reverse display bytes
        vout=1,
        amount=25000000000,
        scriptpubkey=bytes.fromhex(utxo_scriptpubkey),
        block_height=140496
    )
    test_ctx = ExecutionContext(
        tx=test_tx,
        utxo=test_utxo,
        input_index=0
    )
    test_p2pk_key = P2PK_Key.from_bytes(bytes.fromhex(p2pk_key))
    test_p2pk_sig = P2PK_Sig.from_bytes(bytes.fromhex(p2pk_sig))

    # Validate
    engine = ScriptEngine()
    assert engine.validate_script_pair(test_p2pk_key, test_p2pk_sig, test_ctx), \
        "Failed to validate known p2pk Script pair"
