"""
Tests for the script engine

For reference - we look at the transaction containing the scriptsig. This references an unspent UTXO - which is
created from a previous transactions data + a specific TxOutput.

"""
# from src.script import ExecutionContext, P2PK_Sig, P2PK_Key, ScriptEngine
from src.script.context import ExecutionContext
from src.script.script_engine import ScriptEngine
from src.script.scriptpubkey import P2PK_Key, P2PKH_Key, P2MS_Key
from src.script.scriptsig import P2PK_Sig, P2PKH_Sig, P2MS_Sig
from src.tx import Transaction, UTXO

# --- HEX Strings for Known elements --- #
# P2PK
p2pk_tx = \
    "01000000019d7a3553c3faec3d88d18b36ec3bfcdf00c7639ea161205a02e7fc9a1a25b61d0100000049483045022100c219a522e65ca8500ebe05a70d5a49d840ccc15f2afa4ee9df783f06b2a322310220489a46c37feb33f52c586da25c70113b8eea41216440eb84771cb67a67fdb68c01ffffffff0200f2052a010000001976a914e32acf8e6718a32029dc395cca1e0ac45c33f14188ac00c817a8040000004341049464205950188c29d377eebca6535e0f3699ce4069ecd77ffebfbd0bcf95e3c134cb7d2742d800a12df41413a09ef87a80516353a2f0a280547bb5512dc03da8ac00000000"
utxo_display_txid = "1db6251a9afce7025a2061a19e63c700dffc3bec368bd1883decfac353357a9d"
p2pk_key = \
    "41049464205950188c29d377eebca6535e0f3699ce4069ecd77ffebfbd0bcf95e3c134cb7d2742d800a12df41413a09ef87a80516353a2f0a280547bb5512dc03da8ac"
p2pk_sig = \
    "483045022100c219a522e65ca8500ebe05a70d5a49d840ccc15f2afa4ee9df783f06b2a322310220489a46c37feb33f52c586da25c70113b8eea41216440eb84771cb67a67fdb68c01"

# P2PKH
p2pkh_tx = \
    "0100000001a4e61ed60e66af9f7ca4f2eb25234f6e32e0cb8f6099db21a2462c42de61640b010000006b483045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1037952ce26e91e02205aa5f8f88f29bb4ad5808ebc12abfd26bd791256f367b04c6d955f01f28a7724012103f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31feffffff02f9243751130000001976a9140c443537e6e31f06e6edb2d4bb80f8481e2831ac88ac14206c00000000001976a914d807ded709af8893f02cdc30a37994429fa248ca88ac751a0600"
p2pkh_utxo_display_txid = "0b6461de422c46a221db99608fcbe0326e4f2325ebf2a47c9faf660ed61ee6a4"
p2pkh_key = "76a91455ae51684c43435da751ac8d2173b2652eb6410588ac"
p2pkh_sig = \
    "483045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1037952ce26e91e02205aa5f8f88f29bb4ad5808ebc12abfd26bd791256f367b04c6d955f01f28a7724012103f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31"

# P2MS
p2ms_tx = \
    "010000000110a5fee9786a9d2d72c25525e52dd70cbd9035d5152fac83b62d3aa7e2301d58000000009300483045022100af204ef91b8dba5884df50f87219ccef22014c21dd05aa44470d4ed800b7f6e40220428fe058684db1bb2bfb6061bff67048592c574effc217f0d150daedcf36787601483045022100e8547aa2c2a2761a5a28806d3ae0d1bbf0aeff782f9081dfea67b86cacb321340220771a166929469c34959daf726a2ac0c253f9aff391e58a3c7cb46d8b7e0fdc4801ffffffff0180a21900000000001976a914971802edf585cdbc4e57017d6e5142515c1e502888ac00000000"
p2ms_utxo_display_txid = "581d30e2a73a2db683ac2f15d53590bd0cd72de52555c2722d9d6a78e9fea510"
p2ms_sig = \
    "00483045022100af204ef91b8dba5884df50f87219ccef22014c21dd05aa44470d4ed800b7f6e40220428fe058684db1bb2bfb6061bff67048592c574effc217f0d150daedcf36787601483045022100e8547aa2c2a2761a5a28806d3ae0d1bbf0aeff782f9081dfea67b86cacb321340220771a166929469c34959daf726a2ac0c253f9aff391e58a3c7cb46d8b7e0fdc4801"
p2ms_key = \
    "524104d81fd577272bbe73308c93009eec5dc9fc319fc1ee2e7066e17220a5d47a18314578be2faea34b9f1f8ca078f8621acd4bc22897b03daa422b9bf56646b342a24104ec3afff0b2b66e8152e9018fe3be3fc92b30bf886b3487a525997d00fd9da2d012dce5d5275854adc3106572a5d1e12d4211b228429f5a7b2f7ba92eb0475bb14104b49b496684b02855bc32f5daefa2e2e406db4418f3b86bca5195600951c7d918cdbe5e6d3736ec2abf2dd7610995c3086976b2c0c7b4e459d10b34a316d5a5e753ae"


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
        scriptpubkey=bytes.fromhex(p2pk_key),
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


def test_p2pkh_pair():
    """
    We validate a known P2PKH pair of ScriptPubKey | ScriptSig
    """
    # Setup
    test_tx = Transaction.from_bytes(bytes.fromhex(p2pkh_tx))
    test_utxo = UTXO(
        txid=bytes.fromhex(p2pkh_utxo_display_txid)[::-1],  # Reverse display bytes
        vout=1,
        amount=82974043165,
        scriptpubkey=bytes.fromhex(p2pkh_key),
        block_height=399983
    )
    test_ctx = ExecutionContext(
        tx=test_tx,
        utxo=test_utxo,
        input_index=0
    )
    test_p2pkh_key = P2PKH_Key.from_bytes(bytes.fromhex(p2pkh_key))
    test_p2pkh_sig = P2PKH_Sig.from_bytes(bytes.fromhex(p2pkh_sig))

    # Validate
    engine = ScriptEngine()
    assert engine.validate_script_pair(test_p2pkh_key, test_p2pkh_sig, test_ctx), \
        "Failed to validate known p2pkh Script pair"


def test_p2ms_pair():
    # Setup
    test_tx = Transaction.from_bytes(bytes.fromhex(p2ms_tx))
    test_utxo = UTXO(
        txid=bytes.fromhex(p2ms_utxo_display_txid)[::-1],  # Reverse display bytes
        vout=0,
        amount=1690000,
        scriptpubkey=bytes.fromhex(p2ms_key),
        block_height=442241
    )
    test_ctx = ExecutionContext(
        tx=test_tx,
        utxo=test_utxo,
        input_index=0
    )
    test_p2ms_key = P2MS_Key.from_bytes(bytes.fromhex(p2ms_key))
    test_p2ms_sig = P2MS_Sig.from_bytes(bytes.fromhex(p2ms_sig))

    # Validate
    engine = ScriptEngine()
    assert engine.validate_script_pair(test_p2ms_key, test_p2ms_sig, test_ctx), \
        "Failed to validate known P2MS Script pair"
