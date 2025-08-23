"""
Testing script tree using the unbalanced tree provided by LMAB:

Example
┌────────┐ ┌────────┐
│ leaf 1 │ │ leaf 2 │
└───┬────┘ └───┬────┘
    └────┬─────┘
     ┌───┴────┐ ┌────────┐
     │branch 1│ │ leaf 3 │
     └───┬────┘ └─────┬──┘
         └─────┬──────┘
           ┌───┴────┐ ┌────────┐
           │branch 2│ │ leaf 4 │
           └───┬────┘ └────┬───┘
               └────┬──────┘
                ┌───┴────┐ ┌────────┐
                │branch 3│ │ leaf 5 │
                └───┬────┘ └────┬───┘
                    └─────┬─────┘
                      ┌───┴────┐
                      │branch 4│
                      └────────┘

leaf 1 version      = c0
size(leaf 1 script) = 02
leaf 1 script       = 5187
leaf 1 hash         = 6b13becdaf0eee497e2f304adcfa1c0c9e84561c9989b7f2b5fc39f5f90a60f6

leaf 2 version      = c0
size(leaf 2 script) = 02
leaf 2 script       = 5287
leaf 2 hash         = ed5af8352e2a54cce8d3ea326beb7907efa850bdfe3711cef9060c7bb5bcf59e

leaf 3 version      = c0
size(leaf 3 script) = 02
leaf 3 script       = 5387
leaf 3 hash         = 160bd30406f8d5333be044e6d2d14624470495da8a3f91242ce338599b233931

leaf 4 version      = c0
size(leaf 4 script) = 02
leaf 4 script       = 5487
leaf 4 hash         = bf2c4bf1ca72f7b8538e9df9bdfd3ba4c305ad11587f12bbfafa00d58ad6051d

leaf 5 version      = c0
size(leaf 5 script) = 02
leaf 5 script       = 5587
leaf 5 hash         = 54962df196af2827a86f4bde3cf7d7c1a9dcb6e17f660badefbc892309bb145f

branch 1 (leaf 1 hash + leaf 2 hash) = 1324300a84045033ec539f60c70d582c48b9acf04150da091694d83171b44ec9
branch 2 (branch 1 + leaf 3 hash)    = beec0122bddd26f642140bcd922e0264ce1e2be5808a41ae58d82e829bc913d7
branch 3 (branch 2 + leaf 4 hash)    = a4e0d9cc12ce2f32069e98247581d5eb9ca0a4cf175771a8df2c53a93dcb0ebd
branch 4 (leaf 5 hash + branch 3)    = b5b72eea07b3e338962944a752a98772bbe1f1b6550e6fb6ab8c6e6adb152e7c

NOTE: For branch 4, the leaf 5 hash goes first because it's lower than the branch 3 hash.

"""

from src.script import ScriptTree


def test_script_tree():
    leaf_script1 = bytes.fromhex("5187")
    leaf_script2 = bytes.fromhex("5287")
    leaf_script3 = bytes.fromhex("5387")
    leaf_script4 = bytes.fromhex("5487")
    leaf_script5 = bytes.fromhex("5587")

    test_leaves = [leaf_script1, leaf_script2, leaf_script3, leaf_script4, leaf_script5]

    test_tree = ScriptTree(test_leaves, balanced=False)

    mp1 = test_tree.get_merkle_path(leaf_script1)
    mp2 = test_tree.get_merkle_path(leaf_script2)
    mp3 = test_tree.get_merkle_path(leaf_script3)
    mp4 = test_tree.get_merkle_path(leaf_script4)
    mp5 = test_tree.get_merkle_path(leaf_script5)

    _paths = [mp1, mp2, mp3, mp4, mp5]
    _scripts = [leaf_script1, leaf_script2, leaf_script3, leaf_script4, leaf_script5]

    for x in range(len(_paths)):
        temp_path = _paths[x]
        temp_script = _scripts[x]
        calc_root = test_tree.eval_merkle_path(temp_script, temp_path)
        assert calc_root == test_tree.root, f"Failed merkle path for leaf {x + 1}"
