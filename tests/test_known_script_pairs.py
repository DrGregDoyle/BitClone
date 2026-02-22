"""
Tests for the script engine

For reference - we look at the transaction containing the scriptsig. This references an unspent UTXO - which is
created from a previous transactions data + a specific TxOutput.

"""
from src.core import OPCODES, TX
from src.core.byte_stream import serialize_data
from src.data import Leaf, get_control_block, TweakPubkey
from src.script.context import ExecutionContext
from src.script.script_types import P2PK_Key, P2PKH_Key, P2MS_Key, P2SH_Key, P2WPKH_Key, P2WSH_Key, P2TR_Key, \
    P2PK_Sig, \
    P2PKH_Sig, P2MS_Sig, P2SH_Sig, P2SH_P2WPKH_Sig
from src.tx import Transaction, Witness
from src.tx.tx import UTXO

OP_PUSHBYTES_20 = OPCODES.get_byte("OP_PUSHBYTES_20")
OP_PUSHBYTES_22 = OPCODES.get_byte("OP_PUSHBYTES_22")
OP_PUSHBYTES_25 = OPCODES.get_byte("OP_PUSHBYTES_25")
OP_DUP = OPCODES.get_byte("OP_DUP")
OP_HASH160 = OPCODES.get_byte("OP_HASH160")
OP_EQUALVERIFY = OPCODES.get_byte("OP_EQUALVERIFY")
OP_CHECKSIG = OPCODES.get_byte("OP_CHECKSIG")


def test_p2pk_pair(script_engine):
    # Known byte values
    p2pk_key_bytes = bytes.fromhex(
        "41049464205950188c29d377eebca6535e0f3699ce4069ecd77ffebfbd0bcf95e3c134cb7d2742d800a12df41413a09ef87a80516353a2f0a280547bb5512dc03da8ac")
    p2pk_tx_bytes = bytes.fromhex(
        "01000000019d7a3553c3faec3d88d18b36ec3bfcdf00c7639ea161205a02e7fc9a1a25b61d0100000049483045022100c219a522e65ca8500ebe05a70d5a49d840ccc15f2afa4ee9df783f06b2a322310220489a46c37feb33f52c586da25c70113b8eea41216440eb84771cb67a67fdb68c01ffffffff0200f2052a010000001976a914e32acf8e6718a32029dc395cca1e0ac45c33f14188ac00c817a8040000004341049464205950188c29d377eebca6535e0f3699ce4069ecd77ffebfbd0bcf95e3c134cb7d2742d800a12df41413a09ef87a80516353a2f0a280547bb5512dc03da8ac00000000")
    p2pk_txid_display = bytes.fromhex("1db6251a9afce7025a2061a19e63c700dffc3bec368bd1883decfac353357a9d")
    p2pk_scriptsig_bytes = bytes.fromhex(
        "483045022100c219a522e65ca8500ebe05a70d5a49d840ccc15f2afa4ee9df783f06b2a322310220489a46c37feb33f52c586da25c70113b8eea41216440eb84771cb67a67fdb68c01")

    # Setup
    p2pk_key = P2PK_Key.from_bytes(p2pk_key_bytes)
    p2pk_tx = Transaction.from_bytes(p2pk_tx_bytes)
    p2pk_utxo = UTXO(
        outpoint=p2pk_txid_display[::-1] + (1).to_bytes(TX.VOUT, "little"),
        amount=25000000000,
        scriptpubkey=p2pk_key.script,
        block_height=140496
    )
    p2pk_ctx = ExecutionContext(
        tx=p2pk_tx,
        utxo=p2pk_utxo,
        input_index=0
    )
    p2pk_scriptsig = P2PK_Sig.from_bytes(p2pk_scriptsig_bytes)

    # # Validate
    valid_spend = script_engine.validate_script_pair(p2pk_key, p2pk_scriptsig, p2pk_ctx)
    assert valid_spend, "Failed to validate known p2pk Script pair"


def test_p2pkh_pair(script_engine):
    """
    We validate a known P2PKH pair of ScriptPubKey | ScriptSig
    """
    # --- Known byte values
    p2pkh_key_bytes = bytes.fromhex("76a91455ae51684c43435da751ac8d2173b2652eb6410588ac")
    p2pkh_txid_display = bytes.fromhex("0b6461de422c46a221db99608fcbe0326e4f2325ebf2a47c9faf660ed61ee6a4")
    p2pkh_tx_bytes = bytes.fromhex(
        "0100000001a4e61ed60e66af9f7ca4f2eb25234f6e32e0cb8f6099db21a2462c42de61640b010000006b483045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1037952ce26e91e02205aa5f8f88f29bb4ad5808ebc12abfd26bd791256f367b04c6d955f01f28a7724012103f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31feffffff02f9243751130000001976a9140c443537e6e31f06e6edb2d4bb80f8481e2831ac88ac14206c00000000001976a914d807ded709af8893f02cdc30a37994429fa248ca88ac751a0600")
    p2pkh_sig_bytes = bytes.fromhex(
        "483045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1037952ce26e91e02205aa5f8f88f29bb4ad5808ebc12abfd26bd791256f367b04c6d955f01f28a7724012103f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31")

    # --- Construct elements
    p2pkh_key = P2PKH_Key.from_bytes(p2pkh_key_bytes)
    p2pkh_sig = P2PKH_Sig.from_bytes(p2pkh_sig_bytes)
    p2pkh_tx = Transaction.from_bytes(p2pkh_tx_bytes)
    p2pkh_utxo = UTXO(
        outpoint=p2pkh_txid_display[::-1] + (1).to_bytes(TX.VOUT, "little"),  # Reverse display bytes
        amount=82974043165,
        scriptpubkey=p2pkh_key.script,
        block_height=39983
    )
    p2pkh_ctx = ExecutionContext(
        tx=p2pkh_tx,
        input_index=0,
        utxo=p2pkh_utxo
    )

    # --- Validate
    valid_spend = script_engine.validate_script_pair(p2pkh_key, p2pkh_sig, p2pkh_ctx)
    assert valid_spend, "Failed to validate known p2pkh spend pair"


def test_p2ms_pair(script_engine):
    # --- Known byte values
    p2ms_key_bytes = bytes.fromhex(
        "524104d81fd577272bbe73308c93009eec5dc9fc319fc1ee2e7066e17220a5d47a18314578be2faea34b9f1f8ca078f8621acd4bc22897b03daa422b9bf56646b342a24104ec3afff0b2b66e8152e9018fe3be3fc92b30bf886b3487a525997d00fd9da2d012dce5d5275854adc3106572a5d1e12d4211b228429f5a7b2f7ba92eb0475bb14104b49b496684b02855bc32f5daefa2e2e406db4418f3b86bca5195600951c7d918cdbe5e6d3736ec2abf2dd7610995c3086976b2c0c7b4e459d10b34a316d5a5e753ae")
    p2ms_sig_bytes = bytes.fromhex(
        "00483045022100af204ef91b8dba5884df50f87219ccef22014c21dd05aa44470d4ed800b7f6e40220428fe058684db1bb2bfb6061bff67048592c574effc217f0d150daedcf36787601483045022100e8547aa2c2a2761a5a28806d3ae0d1bbf0aeff782f9081dfea67b86cacb321340220771a166929469c34959daf726a2ac0c253f9aff391e58a3c7cb46d8b7e0fdc4801")
    p2ms_txid_display = bytes.fromhex("581d30e2a73a2db683ac2f15d53590bd0cd72de52555c2722d9d6a78e9fea510")
    p2ms_tx_bytes = bytes.fromhex(
        "010000000110a5fee9786a9d2d72c25525e52dd70cbd9035d5152fac83b62d3aa7e2301d58000000009300483045022100af204ef91b8dba5884df50f87219ccef22014c21dd05aa44470d4ed800b7f6e40220428fe058684db1bb2bfb6061bff67048592c574effc217f0d150daedcf36787601483045022100e8547aa2c2a2761a5a28806d3ae0d1bbf0aeff782f9081dfea67b86cacb321340220771a166929469c34959daf726a2ac0c253f9aff391e58a3c7cb46d8b7e0fdc4801ffffffff0180a21900000000001976a914971802edf585cdbc4e57017d6e5142515c1e502888ac00000000")

    # --- Construct elements
    p2ms_key = P2MS_Key.from_bytes(p2ms_key_bytes)
    p2ms_sig = P2MS_Sig.from_bytes(p2ms_sig_bytes)
    p2ms_tx = Transaction.from_bytes(p2ms_tx_bytes)
    p2ms_utxo = UTXO(
        outpoint=p2ms_txid_display[::-1] + (0).to_bytes(TX.VOUT, "little"),  # Reverse display bytes
        amount=1690000,
        scriptpubkey=p2ms_key.script,
        block_height=442241
    )
    p2ms_ctx = ExecutionContext(
        tx=p2ms_tx,
        input_index=0,
        utxo=p2ms_utxo
    )

    # --- validate
    valid_spend = script_engine.validate_script_pair(p2ms_key, p2ms_sig, p2ms_ctx)
    assert valid_spend, "Failed to validate known p2ms spend pair"


def test_p2sh_p2ms_pair(script_engine):
    # --- Known byte values
    p2sh_p2ms_key_bytes = bytes.fromhex("a914748284390f9e263a4b766a75d0633c50426eb87587")
    p2sh_p2ms_sig_bytes = bytes.fromhex(
        "00473044022100d0ed946330182916da16a6149cd313a4b1a7b41591ee52fb3e79d64e36139d66021f6ccf173040ef24cb45c4db3e9c771c938a1ba2cf8d2404416f70886e360af401475121022afc20bf379bc96a2f4e9e63ffceb8652b2b6a097f63fbee6ecec2a49a48010e2103a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c052ae")
    p2sh_p2ms_tx_bytes = bytes.fromhex(
        "010000000c3e10e0814786d6e02dfab4e2569d01a63191b8449bb0f5b9af580fc754ae83b9000000006c493046022100b387bc213db8a333f737e7e6b47ac5e56ba707e97682c1d6ae1d01e28fcfba620221009b7651bbf054babce6884937d598f845f533bac5dc0ec235b0e3408532b9c6e101210308b4492122999b36c09e50121544aa402cef45cd41970f1be6b71dcbd092a35effffffff40629a5c656e8a9fb80ae8a5d55b80fbb598a059bad06c50fcddf404e932d59e000000006a473044022011097b0f58e39fe1f0df7b3159456b12c3b244dcdf6a0fd138ec17d76d41eb5c02202fb5e7cec4f2efbcc90989693b7b6309fcaa27d6aac71eb3dcef60e27a7e7357012103c241a14762ef670d96c0afa470463512f5f356e0752216d34d55b6bfa38acd93ffffffff5763070e224f18dbc8211e60c05ae31543958b248eb08c9e5989167c60b3c570000000006c49304602210088db31bb970f2e77a745d15b8a31d64734c8a9eca3a24540ffa850c90f8a6f50022100bc43eb2a20d70da74cfb2be8eee69c0c1adf741130792aa882a0cda9f7df4b6f012102b5e2177732d3f19abd0e15ac5ff2d5546f70e3f91674b110ccdee8458554f1acffffffff5b4e96a245f6fbc2efb910e25e9dd7a26e0ef8486eebd50dc658ae7d9719e5fd000000006a4730440220656be7132d238e4a848f0da1c3bdc0e22b475e1b66011e1b0536e18cbfe553f502205c89da6c8dad09f5e171404bf66fc19c7d5d2066d4ff4eff3f0766d31688cc4d012102086323b48e87d7fcacb014a58889f20a9881956bf46898c4ffda84b23c965d31ffffffff6889fe551cb869bf20284c64fc3adc229fded6e11fc8b79ec11bb2e499bd0d6c290000006a4730440220226d97d92d855bb2dad731b0cf339727e0f4449c89b1cc1cff7a9432db2a53fb02203478f549e5997b0dccd6abbc5bb206ce40f706672e27b58e3bab210da105dbcf012103c241a14762ef670d96c0afa470463512f5f356e0752216d34d55b6bfa38acd93ffffffff6a1c310490053bfc791ec646907941d3df59bfa8db1b21789d8780c7489695c1000000006a473044022079913e50a223d46c3800f33a6071651aabeecbcc7c726a78aca04dd2832ebe92022075275dbfadcfcca48fa834e7130d24b1055e9ee1470e0bf7ecdf0d9091b27fdc012102fbb8f0fcb28163dd56e26fd7d4b85b71016e62696e577057ddeac36d08a03e26ffffffff79d87f7daedaee7c6e80059b38cde214fec5e4546fbdccc7c24c01c47dce1c23200000008c493046022100ec02daed0c2ab978f588a0486deef52e62b6aa82297b994fe5486d79f8457acb02210098750e260959d6bbd4d47a018b27ea15493d4cd4cb7c96136282745c41aa1c9b014104658e3e86e3740257ebf67085deb14b877955aac502a6b5dcec0cfe1f3026f27b3a772a189b1bb2c28d026bc626a48710edffa9d40830286b80b3ac5709509974ffffffff9a19e8ede8836c192fe816d80d392bb7bb5453f320a78854a83e46bd9f27bf1e000000006c4930460221008b06d1813afd4f368a9570405df7978dca0b4400d173c937931942d88776bfa4022100a7a85b09e50e12e474b634a22fbe6645227dc13cbba2aaa2a84bb1da5e1dc2f1012103c241a14762ef670d96c0afa470463512f5f356e0752216d34d55b6bfa38acd93ffffffffd3090eb0855eee3d1dba53d68edeca6c368a37d3bba9579da3ac675ece42d7680e0000008a47304402204e2518419626eb846e0ef96fb7eda1d7b954b2821482b771f372484c0e327e560220370108f1a7b4676973585c861f5365d8fc2b2b170d922d6fccb15216976a82f80141044884e2974c370394aae8121735a56eaa7215a6a46661f1ca9454c1b99611ae34903e9515b2902f2a22104d10bfd1c2303b38a14be5f2b62b0591ca0d8bbb6864fffffffff61ff40c78b3e12e7d1f9a9db04a7b7736510014fc15a950d575c159b4b0b7a5000000008c493046022100b9b7c3ac969ee98295ec063c84f05c4bf4ee0d4c25448847d44c8e4af3425af7022100cfc90b396f524c366d66a44fa77502dd6f338a584ce653332bcb8909d14360c00141048501beadf835ce4da4078dce8a9dd57964f91da9d675b3d23d45f0de71a03b24d0daf75f29cd521531d5b4389331fe6891e7e1214710cf73e7dbc91cd41cfcecffffffff4471e66e1622bf197ba49ab31d1bd29b4917af60ce103bb6713ffb709b300c45000000006b483045022100a84f83410eb3b40959830b444a85dc1251486afa6e27288bd22fb5771d09795302207d604b1d1c3f8f2d3a9c2ee1007f6b034f69339d0de4f567c12f54af14e208b6012102cbac13c0b22e24ab33131c69e36bdbbe0218cd7f43dcbf9a4b488aadc8ac23b4ffffffff4471e66e1622bf197ba49ab31d1bd29b4917af60ce103bb6713ffb709b300c45010000009100473044022100d0ed946330182916da16a6149cd313a4b1a7b41591ee52fb3e79d64e36139d66021f6ccf173040ef24cb45c4db3e9c771c938a1ba2cf8d2404416f70886e360af401475121022afc20bf379bc96a2f4e9e63ffceb8652b2b6a097f63fbee6ecec2a49a48010e2103a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c052aeffffffff0196e756080000000017a914748284390f9e263a4b766a75d0633c50426eb8758700000000")
    p2sh_p2ms_txid_display = bytes.fromhex("450c309b70fb3f71b63b10ce60af17499bd21b1db39aa47b19bf22166ee67144")

    # --- Construct elements
    p2sh_p2ms_key = P2SH_Key.from_bytes(p2sh_p2ms_key_bytes)
    p2sh_p2ms_sig = P2SH_Sig.from_bytes(p2sh_p2ms_sig_bytes)
    p2sh_p2ms_tx = Transaction.from_bytes(p2sh_p2ms_tx_bytes)
    p2sh_p2ms_utxo = UTXO(
        outpoint=p2sh_p2ms_txid_display[::-1] + (1).to_bytes(TX.VOUT, "little"),  # Reverse display bytes
        amount=10000000,
        scriptpubkey=p2sh_p2ms_key.script,
        block_height=183729
    )
    p2sh_p2ms_ctx = ExecutionContext(
        tx=p2sh_p2ms_tx,
        input_index=11,
        utxo=p2sh_p2ms_utxo
    )

    # --- Validate
    valid_spend = script_engine.validate_script_pair(p2sh_p2ms_key, p2sh_p2ms_sig, p2sh_p2ms_ctx)
    assert valid_spend, "Failed to validate known P2SH Script pair"


def test_p2sh_p2wpkh_pair(script_engine):
    # --- Known byte values
    p2sh_key_bytes = bytes.fromhex("a9146d3ed4cf55dc6752a12d3091d436ef8f0f982ff887")
    p2wpkh_key_bytes = bytes.fromhex("001402c8147af586cace7589672191bb1c790e9e9a72")
    p2sh_p2wpkh_sig_bytes = bytes.fromhex("16001402c8147af586cace7589672191bb1c790e9e9a72")
    p2sh_p2wpkh_tx_bytes = bytes.fromhex(
        "0200000000010d4e5a75b4b55367073123ac4b351875be832a387a3f1aec4b508bdb3cdf231e02000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff419ea287480a53e96aaeb95db362eb4a608cabccb82ba78a701ea63a0b23af14000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff604b150686c6459235e69be6202154634639b81088d5f7011e31665c2a5a371f010000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffffe576dfe9c5c52146c666e2f554feb2dd2ad470cd03130a4b7ddaeef5ccfcc31f010000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff0c3e97ca785fdf883b240bc7cbc407de6c4689aaf1368480fafabf6196702639000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff4529bc7981a486dae2cdf12a058816fac5a73ff283c8e2d3eb057da9b927d34c010000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffffa102354da66de20c297bd16eb5d01eef1460e0dcd6ffac5d415c7fdbc1b01b78410000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff5fe060edff8c3317f86f4c0f3924f26d3614b72f2ed28461f6194d07daa3f587000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffffa7b5e7eed6977fced331d6584dd2268c83c03b9bcf5959a0ebdf765c50f7e18f000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdfffffff23eada5b5a698ce09738bd0d50f9fa5d0dbfcbf858f6452ca798f347c889ad9010000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff775b6257bb283ceb283d313feb86a59eb1791f6f0cd370b584e1ca45642817e3000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff8d206dea8e821433af2a861ec6d37afcb643b8e2cd593673214e6f68e96913ea000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdfffffffdc64af7edb03bca45cdb62cd605c7fc9f7bbacf928b46a075c9fbefcf2630ed000000008a4730440220730e055cefab7ac3120dd9e7fe7e9490c6b88b1dd2184635b15512e23d618d8302206f6aa6911e2e3ec348021633334c75b75486548fea38354e5aa772272e02a6cd01410408b281209f4e42f7a85a459eb19b65154a4eb078282bf58382f30eae58d249659cb67bc5e52afb23470dca828ff1193d43b46779d330332e3e1fd32955e5379bfdffffff010715990600000000160014907189739c6255dce21f61cc906707f949322add0247304402201f85ab44217563b4ce9d11e4c7b00dc59dd102099eb250634f4b6906276ba07702206147cc98f29c5fcbad925b5e40fe154f4d429f9569f292f9298f615c494004450121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c024730440220346d5b3ef82fcd35618cce141925474cc4a652c2bbedc54605af267f08f98dad022020b630ea92f193d30f36841bfacdaf7f21d877745a01cd70fb6f1ed8726165680121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c02473044022008e762cf7163c6adbd56d53648849fd6a606a65a4bd4888c3d8f55168afd13d002202778e6ac8eb2e6f35facef2e6fda07d7c39e44759a2c4e4253f895d02328b9900121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402207cf547a4f22aec344ec1b3cc7db7c2a63db1a1a9b8626aaeb32c9b2546e361f5022053fe8dcbc1bd133765b5caf95ff9db5c34a4066b25acb2df2791e193c823cc370121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c02473044022004c3c5517599fdf88c6209237a2b113cf4a4500538dfeee21c93f68c067319e202206a44299a0e9a45896f51d37a6b64d9587b6093a527fd8ccc129715fb4e3235e80121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402206268b59fb737258d90be572e89edca479826986a2be599b20b6000c4c131ae8c02204ca861d33240d0dadeb437c4e849a700b455847609a810e6236a71cda58a8ba90121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402205710dbfb624e0e05fe4b9874386c93084e88b89e16eb94608d6a92e451f5f3cd0220570367db12e3d07de3f08c735f3a3e719b6f78f87a7e20baf1f3db01764451bf0121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402206d43fe58a74044fc81df8b10854a4067af4c7fe1b61992818c2bac30eb5cb28b02204a58491439771f897a087748df55e78b6d63a7105f83491aac408e446391dac70121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c02473044022062599a99c5e7bcbce1fe649869cd017d7107a63550fa67c1677039f1ab4b593402201a4c271c3c0792d28d78338a97c3651de329e0cde31fb610157bf026f22b68e00121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402207b7bfd5c8abf833d2a9b10f95749e596eab49fd77ce9237fcfbb804be492d3ed02207a85b47a0ba69e483dd411e4da9c0470b6bf21664096be160067dd674701980e0121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402206d7db777e15bf1974aec93ce65d02802ded6ee2055dd890698e573f22b02f55e02206e21249c21f72700b583365ed111d1d172452175d8bb870e7076d6a4b3e529d50121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402202af8e3170475f06e91a26fe2c666d745406b91b9a063ec0513062f0e982a219f02200d6f865b3dc4eae5fcb2eb11fc15cefdb5d0c4868f2dd2a17f981d3065e28f280121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0081a80c00")
    p2sh_p2wpkh_txid_display = bytes.fromhex("021e23df3cdb8b504bec1a3f7a382a83be7518354bac2331076753b5b4755a4e")
    p2sh_p2wpkh_pubkey_hash = bytes.fromhex("02c8147af586cace7589672191bb1c790e9e9a72")

    # --- Construct elements
    p2sh_key = P2SH_Key.from_bytes(p2sh_key_bytes)
    p2wpkh_key = P2WPKH_Key.from_bytes(p2wpkh_key_bytes)
    p2sh_p2wpkh_sig = P2SH_P2WPKH_Sig.from_bytes(p2sh_p2wpkh_sig_bytes)
    p2sh_p2wpkh_tx = Transaction.from_bytes(p2sh_p2wpkh_tx_bytes)
    p2sh_p2wpkh_utxo = UTXO(
        outpoint=p2sh_p2wpkh_txid_display[::-1] + (0).to_bytes(TX.VOUT, "little"),  # Reverse display bytes
        amount=25552,
        scriptpubkey=p2sh_key.script,
        block_height=826281
    )
    p2sh_p2wpkh_scriptcode = (OP_PUSHBYTES_25 + OP_DUP + OP_HASH160 + OP_PUSHBYTES_20 + p2sh_p2wpkh_pubkey_hash +
                              OP_EQUALVERIFY + OP_CHECKSIG)
    p2sh_p2wpkh_ctx = ExecutionContext(
        tx=p2sh_p2wpkh_tx,
        input_index=0,
        utxo=p2sh_p2wpkh_utxo,
        is_segwit=True,
        script_code=p2sh_p2wpkh_scriptcode
    )

    # --- Validate
    # Validate p2wpkh key against p2sh_p2wpkh_sig
    assert OP_PUSHBYTES_22 + p2wpkh_key.script == p2sh_p2wpkh_sig.script, "P2WPKH doesn't agree with P2SH-P2WPKH " \
                                                                          "ScriptSig"

    valid_spend = script_engine.validate_script_pair(p2sh_key, p2sh_p2wpkh_sig, p2sh_p2wpkh_ctx)
    assert valid_spend, "Failed to validate known P2SH-P2WPKH spend pair"


def test_p2wpkh(script_engine):
    # --- Known byte values
    p2wpkh_key_bytes = bytes.fromhex("0014841b80d2cc75f5345c482af96294d04fdd66b2b7")
    p2wpkh_witsig = bytes.fromhex(
        "3045022100c7fb3bd38bdceb315a28a0793d85f31e4e1d9983122b4a5de741d6ddca5caf8202207b2821abd7a1a2157a9d5e69d2fdba3502b0a96be809c34981f8445555bdafdb01")
    p2wpkh_tx_bytes = bytes.fromhex(
        "020000000001013aa815ace3c5751ee6c325d614044ad58c18ed2858a44f9d9f98fbcddad878c10000000000ffffffff01344d10000000000016001430cd68883f558464ec7939d9f960956422018f0702483045022100c7fb3bd38bdceb315a28a0793d85f31e4e1d9983122b4a5de741d6ddca5caf8202207b2821abd7a1a2157a9d5e69d2fdba3502b0a96be809c34981f8445555bdafdb012103f465315805ed271eb972e43d84d2a9e19494d10151d9f6adb32b8534bfd764ab00000000")
    p2wpkh_witpubkey = bytes.fromhex("03f465315805ed271eb972e43d84d2a9e19494d10151d9f6adb32b8534bfd764ab")
    p2wpkh_scriptcode_bytes = bytes.fromhex("841b80d2cc75f5345c482af96294d04fdd66b2b7")
    p2wpkh_txid_bytes = bytes.fromhex("c178d8dacdfb989f9d4fa45828ed188cd54a0414d625c3e61e75c5e3ac15a83a")  # Display

    # --- Construct objects
    p2wpkh_key = P2WPKH_Key.from_bytes(p2wpkh_key_bytes)
    p2wpkh_witness = Witness([p2wpkh_witsig, p2wpkh_witpubkey])
    p2wpkh_tx = Transaction.from_bytes(p2wpkh_tx_bytes)
    p2wpkh_utxo = UTXO(
        outpoint=p2wpkh_txid_bytes[::-1] + (0).to_bytes(TX.VOUT, "little"),  # Reverse display bytes for use
        amount=1083200,
        scriptpubkey=p2wpkh_key.script
    )

    p2wpkh_scriptcode = (OP_PUSHBYTES_25 + OP_DUP + OP_HASH160 + OP_PUSHBYTES_20 + p2wpkh_scriptcode_bytes
                         + OP_EQUALVERIFY + OP_CHECKSIG)

    p2wpkh_ctx = ExecutionContext(
        tx=p2wpkh_tx,
        input_index=0,
        utxo=p2wpkh_utxo,
        is_segwit=True,
        script_code=p2wpkh_scriptcode
    )

    # Validate
    # Check that witness is in tx
    tx_witness = p2wpkh_tx.witness[0]
    assert p2wpkh_witness == tx_witness, "Failed to create same witnesses for known tx"
    # Verify spend pair
    valid_spend = script_engine.validate_segwit(p2wpkh_key, p2wpkh_ctx)
    assert valid_spend, "Failed to validate know P2WPKH spend pair."


def test_p2wsh(script_engine):
    # --- KNOWN VALUES
    # Scriptpubkey
    p2wsh_key = P2WSH_Key.from_bytes(
        bytes.fromhex("002065f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3")
    )

    # UTXO (outpoint, amount, scriptpubkey, blockheight)
    p2wsh_utxo = UTXO(
        # Reverse display bytes
        outpoint=bytes.fromhex("46ebe264b0115a439732554b2b390b11b332b5b5692958b1754aa0ee57b64265")[::-1] + (1).to_bytes(
            TX.VOUT, "little"),
        amount=53519352,
        scriptpubkey=p2wsh_key.script,
        block_height=630000
    )

    # Witness
    p2wsh_witness = Witness.from_bytes(
        bytes.fromhex(
            "04004730440220415899bbee08e42376d06e8f86c92b4987613c2816352fe09cd1479fd639f18c02200db57f508f69e266d76c23891708158bda18690c165a41b0aa88303b97609f780147304402203973de2303e8787767090dd25c8a4dc97ce1aa7eb4c0962f13952ed4e856ff8e02203f1bb425def789eea8be46407d10b3c8730407176aef4dc2c29865eb5e5542bf0169522103848e308569b644372a5eb26665f1a8c34ca393c130b376db2fae75c43500013c2103cec1ee615c17e06d4f4b0a08617dffb8e568936bdff18fb057832a58ad4d1b752103eed7ae80c34d70f5ba93f93965f69f3c691da0f4607f242f4fd6c7a48789233e53ae")
    )
    p2wsh_witness_script = p2wsh_witness.items[-1]  # Last data in p2wsh witness field is the witness script for hashing

    # Tx
    p2wsh_tx = Transaction.from_bytes(
        bytes.fromhex(
            "010000000001016542b657eea04a75b1582969b5b532b3110b392b4b553297435a11b064e2eb460100000000ffffffff02c454fd000000000017a9145e7be6ec3e2382c669aaf3c71da1056f47b9024d875b07330200000000220020ea166bf0492c6f908e45404932e0f39c0571a71007c22b872548cd20f19a92f504004730440220415899bbee08e42376d06e8f86c92b4987613c2816352fe09cd1479fd639f18c02200db57f508f69e266d76c23891708158bda18690c165a41b0aa88303b97609f780147304402203973de2303e8787767090dd25c8a4dc97ce1aa7eb4c0962f13952ed4e856ff8e02203f1bb425def789eea8be46407d10b3c8730407176aef4dc2c29865eb5e5542bf0169522103848e308569b644372a5eb26665f1a8c34ca393c130b376db2fae75c43500013c2103cec1ee615c17e06d4f4b0a08617dffb8e568936bdff18fb057832a58ad4d1b752103eed7ae80c34d70f5ba93f93965f69f3c691da0f4607f242f4fd6c7a48789233e53aeee9c0900")
    )

    # Context
    p2wsh_ctx = ExecutionContext(
        tx=p2wsh_tx,
        input_index=0,
        utxo=p2wsh_utxo,
        is_segwit=True,
        script_code=serialize_data(p2wsh_witness_script)
    )

    # --- Evaluate
    valid_spend = script_engine.validate_segwit(p2wsh_key, p2wsh_ctx)
    assert valid_spend, "Failed known P2WSH pair."


def test_keypath(script_engine):
    # --- Known values
    p2tr_key = P2TR_Key(
        xonly_pubkey=bytes.fromhex("924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329")
    )

    p2tr_utxo = UTXO(
        # reverse display bytes
        outpoint=bytes.fromhex("a7115c7267dbb4aab62b37818d431b784fe731f4d2f9fa0939a9980d581690ec")[::-1] + (0).to_bytes(
            TX.VOUT, "little"),
        amount=20000,
        scriptpubkey=p2tr_key.script,
        block_height=861957
    )

    p2tr_tx = Transaction.from_bytes(
        bytes.fromhex(
            "02000000000101ec9016580d98a93909faf9d2f431e74f781b438d81372bb6aab4db67725c11a70000000000ffffffff0110270000000000001600144e44ca792ce545acba99d41304460dd1f53be3840141b693a0797b24bae12ed0516a2f5ba765618dca89b75e498ba5b745b71644362298a45ca39230d10a02ee6290a91cebf9839600f7e35158a447ea182ea0e022ae0100000000")
    )

    p2tr_ctx = ExecutionContext(
        tx=p2tr_tx,
        input_index=0,
        utxo=p2tr_utxo,
        is_segwit=True,
        tapscript=True
    )

    # --- Validate script
    valid_spend = script_engine.validate_segwit(scriptpubkey=p2tr_key, ctx=p2tr_ctx)
    assert valid_spend, "Failed to validate known key-path spend"


def test_simple_spendpath(script_engine):
    # --- Known byte values
    p2tr_xonly_pubkey_bytes = bytes.fromhex("924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329")
    p2tr_leaf_script = bytes.fromhex("5887")
    p2tr_leaf_inputs = bytes.fromhex("08")
    p2tr_tx_bytes = bytes.fromhex(
        "02000000000102c20da20832c3894854dc63f69cf7fe805323b3d476aaa8e730244b36a575d2440000000000ffffffff87adaa9d7302d05896b0d491a099208c20ea0ac9fa776ddf4b7cafcafaf8c48b0100000000ffffffff010f0e00000000000016001492b8c3a56fac121ddcdffbc85b02fb9ef681038a0247304402200c4c0bfe93f6622fa0790b6d28bf755c1a3f23e8404bb804ca8e2db080b613b102205bcf0a4e4559ba9b40e6b174cf91af061dfa21691923b410e351326708b041a00121030c7196376bc1df61b6da6ee711868fd30e370dd273332bfb02a2287d11e2e9c503010802588721c1924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a332900000000")
    p2tr_txid_display_bytes = bytes.fromhex("8bc4f8facaaf7c4bdf6d77fac90aea208c2099a091d4b09658d002739daaad87")

    # --- Construct elements
    p2tr_leaf = Leaf(p2tr_leaf_script)
    p2tr_key = P2TR_Key(p2tr_xonly_pubkey_bytes, [p2tr_leaf_script])
    p2tr_control_block = get_control_block(p2tr_xonly_pubkey_bytes, p2tr_leaf.leaf_hash)
    p2tr_witness = Witness(items=[p2tr_leaf_inputs, p2tr_leaf_script, p2tr_control_block])
    p2tr_tx = Transaction.from_bytes(p2tr_tx_bytes)
    p2tr_utxo = UTXO(
        outpoint=p2tr_txid_display_bytes[::-1] + (1).to_bytes(TX.VOUT, "little"),
        amount=20000,
        scriptpubkey=p2tr_key.script,
        block_height=862100
    )
    p2tr_context = ExecutionContext(
        tx=p2tr_tx,
        input_index=1,
        utxo=p2tr_utxo,
        is_segwit=True,
        tapscript=True
    )

    # Validate
    assert p2tr_witness == p2tr_tx.witness[1], "Failed to construct correct known WitnessField"
    assert script_engine.validate_segwit(p2tr_key, p2tr_context), "Failed to validate known simple script-path spend."


def test_simple_sig_spendpath(script_engine):
    xonly_pubkey = bytes.fromhex("924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329")
    leaf_script = bytes.fromhex("206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac")
    temp_leaf = Leaf(leaf_script)
    tweak_pubkey = TweakPubkey(xonly_pubkey, merkle_root=temp_leaf.leaf_hash)

    p2tr_scriptpubkey = P2TR_Key(xonly_pubkey=xonly_pubkey, scripts=[leaf_script])
    p2tr_utxo = UTXO(
        outpoint=bytes.fromhex("d1c40446c65456a9b11a9dddede31ee34b8d3df83788d98f690225d2958bfe3c")[::-1] + (0).to_bytes(
            TX.VOUT, "little"),
        amount=20000,
        scriptpubkey=p2tr_scriptpubkey.script,
        block_height=863496
    )

    # --- Spend elements
    p2tr_tx = Transaction.from_bytes(
        bytes.fromhex(
            "020000000001013cfe8b95d22502698fd98837f83d8d4be31ee3eddd9d1ab1a95654c64604c4d10000000000ffffffff01983a0000000000001600140de745dc58d8e62e6f47bde30cd5804a82016f9e034101769105cbcbdcaaee5e58cd201ba3152477fda31410df8b91b4aee2c4864c7700615efb425e002f146a39ca0a4f2924566762d9213bd33f825fad83977fba7f0122206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac21c0924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a332900000000")
    )
    ptr2_context = ExecutionContext(
        tx=p2tr_tx,
        input_index=0,
        utxo=p2tr_utxo,
        is_segwit=True,
        tapscript=True,
        merkle_root=temp_leaf.leaf_hash
    )

    # --- Validation
    # Tweaked pubkeys agree
    assert tweak_pubkey.tweaked_pubkey.x_bytes() == p2tr_scriptpubkey.script[2:], "Failed to create known tweaked " \
                                                                                  "pubkey"

    assert script_engine.validate_segwit(p2tr_scriptpubkey,
                                         ptr2_context), "Failed to validate known simple signature script-path spend."


def test_scriptpath_spend(script_engine):
    xonly_pubkey = bytes.fromhex("924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329")
    leaf_scripts = [
        bytes.fromhex("5187"),
        bytes.fromhex("5287"),
        bytes.fromhex("5387"),
        bytes.fromhex("5487"),
        bytes.fromhex("5587")
    ]

    test_p2tr_pubkey = P2TR_Key(xonly_pubkey, leaf_scripts)
    test_p2tr_utxo = UTXO(
        outpoint=bytes.fromhex("ec7b0fdfeb2c115b5a4b172a3a1cf406acc2425229c540d40ec752d893aac0d7")[::-1] + (0).to_bytes(
            TX.VOUT, "little"),
        amount=10000,
        scriptpubkey=test_p2tr_pubkey.script,
        block_height=863632
    )

    # --- Known tx
    known_tx = Transaction.from_bytes(bytes.fromhex(
        "02000000000101d7c0aa93d852c70ed440c5295242c2ac06f41c3a2a174b5a5b112cebdf0f7bec0000000000ffffffff01260100000000000016001492b8c3a56fac121ddcdffbc85b02fb9ef681038a03010302538781c0924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a33291324300a84045033ec539f60c70d582c48b9acf04150da091694d83171b44ec9bf2c4bf1ca72f7b8538e9df9bdfd3ba4c305ad11587f12bbfafa00d58ad6051d54962df196af2827a86f4bde3cf7d7c1a9dcb6e17f660badefbc892309bb145f00000000"))

    test_ctx = ExecutionContext(
        tx=known_tx,
        input_index=0,
        utxo=test_p2tr_utxo,
        tapscript=True,
        is_segwit=True
    )

    script_validated = script_engine.validate_segwit(test_p2tr_pubkey, test_ctx)
    assert script_validated, "Failed to validate known script path spend (tree)"
