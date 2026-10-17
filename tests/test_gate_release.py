"""Gate.record_release: an operator-approved action, library half.

When an operator approves a blocked action and the agent then performs it,
the gate records it as performed, not blocked, so the receipt never asserts a
block that did not happen. The audit chain keeps both beats, and one approval
releases one action. The plane side of the approval protocol stays in the ZTI
Core product tree.
"""

from ztipgate.gate import ALLOW, Contract, Gate


def _gate():
    return Gate(Contract(work_id="w", allowed_paths=["src/**"],
                         forbidden_paths=["secrets/**"], required_checks=[]))


def test_a_released_action_moves_from_blocked_to_completed():
    gate = _gate()
    action = {"type": "write", "path": "docs/x.md"}
    assert gate.check_action(action).decision != ALLOW
    assert len(gate.blocked) == 1 and gate.completed == []
    decision = gate.record_release(action)
    assert decision.decision == ALLOW
    assert decision.reason_code == "APPROVAL_RELEASED"
    assert gate.blocked == [] and gate.completed == [action]


def test_one_approval_releases_only_the_most_recent_matching_block():
    gate = _gate()
    action = {"type": "write", "path": "docs/x.md"}
    gate.check_action(action)
    gate.check_action(action)
    gate.record_release(action)
    assert len(gate.blocked) == 1                 # the earlier block still stands
    assert len(gate.completed) == 1


def test_the_audit_chain_keeps_both_beats():
    gate = _gate()
    action = {"type": "write", "path": "docs/x.md"}
    gate.check_action(action)
    gate.record_release(action)
    chain = gate.audit_chain
    assert chain[-1]["reason_code"] == "APPROVAL_RELEASED"
    assert chain[-2]["decision"] != ALLOW         # the block is still on record
    assert chain[-1]["prev_hash"] == chain[-2]["hash"]
