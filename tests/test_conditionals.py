"""
Comprehensive test suite for conditional scripts (OP_IF / OP_NOTIF / OP_ELSE / OP_ENDIF).

These tests mirror the style of ``test_opcode_execution.py`` by exposing each
scenario as its own pytest test function, while focusing on the behaviour of
OP_RETURN in executed vs non-executed branches.
"""

from __future__ import annotations


def _run_conditional(script_engine, script_hex: str) -> bool:
    """Helper to run ``validate_script`` on a hex-encoded script."""
    script_bytes = bytes.fromhex(script_hex.replace(" ", ""))
    return script_engine.validate_script(script_bytes)


# --- Basic OP_IF tests ----------------------------------------------------- #


def test_if_true_simple_execution(script_engine):
    # OP_1 OP_IF OP_2 OP_ENDIF
    result = _run_conditional(script_engine, "51 63 52 68")
    assert result is True


def test_if_false_skips_branch(script_engine):
    # OP_0 OP_IF OP_2 OP_ENDIF OP_1
    result = _run_conditional(script_engine, "00 63 52 68 51")
    assert result is True


# --- OP_RETURN inside OP_IF branches -------------------------------------- #


def test_if_op_return_in_skipped_branch_is_allowed(script_engine):
    # OP_0 OP_IF OP_RETURN OP_ENDIF OP_1
    result = _run_conditional(script_engine, "00 63 6a 68 51")
    assert result is True


def test_if_op_return_in_executed_branch_fails(script_engine):
    # OP_1 OP_IF OP_RETURN OP_ENDIF OP_2
    test_script = bytes.fromhex("51636a6852")
    # result = _run_conditional(script_engine, "51 63 6a 68 52")
    result = script_engine.validate_script(test_script)
    assert result is False


# --- OP_IF / OP_ELSE tests ------------------------------------------------ #


def test_if_else_true_executes_if(script_engine):
    # OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
    result = _run_conditional(script_engine, "51 63 52 67 53 68")
    assert result is True


def test_if_else_false_executes_else(script_engine):
    # OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
    result = _run_conditional(script_engine, "00 63 52 67 53 68")
    assert result is True


def test_if_else_op_return_in_skipped_else_is_allowed(script_engine):
    # OP_1 OP_IF OP_2 OP_ELSE OP_RETURN OP_ENDIF
    result = _run_conditional(script_engine, "51 63 52 67 6a 68")
    assert result is True


def test_if_else_op_return_in_executed_else_fails(script_engine):
    # OP_0 OP_IF OP_2 OP_ELSE OP_RETURN OP_ENDIF
    result = _run_conditional(script_engine, "00 63 52 67 6a 68")
    assert result is False


def test_if_else_op_return_in_skipped_if_is_allowed(script_engine):
    # OP_0 OP_IF OP_RETURN OP_ELSE OP_2 OP_ENDIF
    result = _run_conditional(script_engine, "00 63 6a 67 52 68")
    assert result is True


# --- OP_NOTIF tests ------------------------------------------------------- #


def test_notif_false_executes_branch(script_engine):
    # OP_0 OP_NOTIF OP_2 OP_ENDIF
    result = _run_conditional(script_engine, "00 64 52 68")
    assert result is True


def test_notif_true_skips_branch(script_engine):
    # OP_1 OP_NOTIF OP_2 OP_ENDIF OP_3
    result = _run_conditional(script_engine, "51 64 52 68 53")
    assert result is True


def test_notif_op_return_in_skipped_branch_is_allowed(script_engine):
    # OP_1 OP_NOTIF OP_RETURN OP_ENDIF OP_2
    result = _run_conditional(script_engine, "51 64 6a 68 52")
    assert result is True


def test_notif_op_return_in_executed_branch_fails(script_engine):
    # OP_0 OP_NOTIF OP_RETURN OP_ENDIF OP_2
    result = _run_conditional(script_engine, "00 64 6a 68 52")
    assert result is False


# --- Nested conditionals -------------------------------------------------- #


def test_nested_if_both_true(script_engine):
    # OP_1 OP_IF OP_1 OP_IF OP_2 OP_ENDIF OP_ENDIF
    result = _run_conditional(script_engine, "51 63 51 63 52 68 68")
    assert result is True


def test_nested_if_outer_true_inner_false(script_engine):
    # OP_1 OP_IF OP_0 OP_IF OP_2 OP_ENDIF OP_3 OP_ENDIF
    result = _run_conditional(script_engine, "51 63 00 63 52 68 53 68")
    assert result is True


def test_nested_if_outer_false_inner_true_never_evaluated(script_engine):
    # OP_0 OP_IF OP_1 OP_IF OP_2 OP_ENDIF OP_ENDIF OP_3
    result = _run_conditional(script_engine, "00 63 51 63 52 68 68 53")
    assert result is True


def test_nested_if_op_return_in_outer_skipped_branch_is_allowed(script_engine):
    # OP_0 OP_IF OP_1 OP_IF OP_RETURN OP_ENDIF OP_ENDIF OP_2
    result = _run_conditional(script_engine, "00 63 51 63 6a 68 68 52")
    assert result is True


def test_nested_if_op_return_in_inner_skipped_branch_is_allowed(script_engine):
    # OP_1 OP_IF OP_0 OP_IF OP_RETURN OP_ENDIF OP_2 OP_ENDIF
    result = _run_conditional(script_engine, "51 63 00 63 6a 68 52 68")
    assert result is True


def test_nested_if_op_return_in_executed_inner_branch_fails(script_engine):
    # OP_1 OP_IF OP_1 OP_IF OP_RETURN OP_ENDIF OP_2 OP_ENDIF
    result = _run_conditional(script_engine, "51 63 51 63 6a 68 52 68")
    assert result is False


def test_nested_if_else_op_return_only_in_non_executed_branches(script_engine):
    """"Nested with ELSE: All branches have OP_RETURN except executed","""
    # OP_1 OP_IF (OP_0 OP_IF *OP_RETURN OP_ELSE OP_1 OP_ENDIF) OP_ELSE *OP_RETURN OP_ENDIF
    result = _run_conditional(script_engine, "51 63 00 63 6a 67 51 68 67 6a 68")
    assert result is True


# --- Edge cases with empty branches -------------------------------------- #


def test_if_else_empty_if_branch(script_engine):
    # OP_1 OP_1 OP_IF OP_ELSE OP_2 OP_ENDIF
    result = _run_conditional(script_engine, "51 51 63 67 52 68")
    assert result is True


def test_if_else_empty_else_branch(script_engine):
    # OP_1 OP_IF OP_2 OP_ELSE OP_ENDIF
    result = _run_conditional(script_engine, "51 63 52 67 68")
    assert result is True


def test_if_else_both_branches_empty(script_engine):
    # OP_1 OP_IF OP_ELSE OP_ENDIF OP_2
    result = _run_conditional(script_engine, "51 63 67 68 52")
    assert result is True
