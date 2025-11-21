"""
These tests are to verify the signature algorithm against known sighash values
"""
from src.data.taproot import Leaf, TweakPubkey, get_control_block, get_control_byte, get_tweak
from src.script.context import SignatureContext
from src.script.scriptpubkey import P2TR_Key
from src.tx.tx import Transaction, WitnessField


def test_known_taproot_sighash(sig_engine):
    # --- KNOWN VALUES --- #
    known_sighash = bytes.fromhex("752453d473e511a0da2097d664d69fe5eb89d8d9d00eab924b42fc0801a980c9")
    known_control_byte = b'\xc0'
    known_control_block = bytes.fromhex("c0924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329")
    known_tweak = bytes.fromhex("479785dd89a6441dbe00c7661865a0cc68672e8021f4547ac7f89ac26ac049f2")

    # We test a known sighash for simple taproot script
    test_leaf_script = bytes.fromhex("206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac")
    test_leaf = Leaf(test_leaf_script)
    test_merkle_root = test_leaf.leaf_hash
    # Get pubkey
    test_xonly_pubkey = bytes.fromhex("924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329")
    test_p2tr_key = P2TR_Key(xonly_pubkey=test_xonly_pubkey, scripts=[test_leaf_script])
    # Get tweaked pubkey
    test_p2tr_tweak = get_tweak(test_xonly_pubkey, test_merkle_root)
    test_p2tr_tweaked_pubkey = TweakPubkey(xonly_pubkey=test_xonly_pubkey, merkle_root=test_merkle_root)

    # --- Construct spend elements
    test_privkey = bytes.fromhex("9b8de5d7f20a8ebb026a82babac3aa47a008debbfde5348962b2c46520bd5189")
    test_control_byte = get_control_byte(test_p2tr_tweaked_pubkey.tweaked_pubkey.to_point())
    test_control_block = get_control_block(test_xonly_pubkey, test_merkle_root)

    test_hashtype = 1  # SIGHASH_ALL
    ext_flag = 1

    test_tx = Transaction.from_bytes(bytes.fromhex(
        "020000000001013cfe8b95d22502698fd98837f83d8d4be31ee3eddd9d1ab1a95654c64604c4d10000000000ffffffff01983a0000000000001600140de745dc58d8e62e6f47bde30cd5804a82016f9e034101769105cbcbdcaaee5e58cd201ba3152477fda31410df8b91b4aee2c4864c7700615efb425e002f146a39ca0a4f2924566762d9213bd33f825fad83977fba7f0122206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac21c0924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a332900000000"
    ))
    backup_tx = Transaction.from_bytes(bytes.fromhex(
        "020000000001013cfe8b95d22502698fd98837f83d8d4be31ee3eddd9d1ab1a95654c64604c4d10000000000ffffffff01983a0000000000001600140de745dc58d8e62e6f47bde30cd5804a82016f9e034101769105cbcbdcaaee5e58cd201ba3152477fda31410df8b91b4aee2c4864c7700615efb425e002f146a39ca0a4f2924566762d9213bd33f825fad83977fba7f0122206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac21c0924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a332900000000"
    ))
    test_tx.witness[0] = WitnessField(items=[])

    sig_ctx = SignatureContext(
        tx=test_tx,
        input_index=0,
        sighash_type=test_hashtype,
        amount=20000,
        amounts=[20000],
        prev_scriptpubkeys=[test_p2tr_key.script],
        ext_flag=ext_flag,
        merkle_root=test_merkle_root,
        # leaf_hash=test_leaf.leaf_hash
    )

    # --- Signature Engine

    signed_tx = sig_engine.sign_taproot_scriptpath(
        tx=test_tx,
        input_index=0,
        privkey=test_privkey,  # internal privkey
        amount=20000,
        xonly_pubkey=test_xonly_pubkey,
        scripts=[test_leaf_script]
    )

    # --- Validation
    # Verify control byte
    assert test_control_byte == known_control_byte, "Failed to recreate known control byte"
    # Verify control block
    assert test_control_block == known_control_block, "Failed to recreate known control block"
    # Verify tweak
    assert test_p2tr_tweak == known_tweak, "Failed to recreat known tweak"

    # Verify sighaash
    assert sig_engine.get_taproot_sighash(sig_ctx) == known_sighash, "Failed to construct known sighash from sig " \
                                                                     "context"

    # Test witnesses
    assert signed_tx.witness[0] == backup_tx.witness[0], "Failed to create correct sighash for taproot witness"
