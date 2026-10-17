"""Every recorded check result names its check type.

A result must say which check it answers and what kind of check that was, or
it certifies nothing. The type on each result matches the requirement it
answers in the request, and it survives into the minted receipt.
"""

from ztipgate.gate import (Contract, Gate, build_authorization_decision,
                           build_transaction_request)


def _contract():
    return Contract(work_id="w", allowed_paths=["**"],
                    required_checks=["check-a", "  ", "check-b"])


def test_every_result_carries_check_type():
    gate = Gate(_contract())
    _, results, _ = gate.verify_completion("succeeded", lambda c: True)
    assert len(results) == 2                      # the blank entry is not a check
    assert all(r["check_type"] == "command" for r in results)


def test_a_check_that_could_not_run_still_names_its_type():
    gate = Gate(_contract())

    def boom(check):
        raise OSError("no shell")
    _, results, reason = gate.verify_completion("succeeded", boom)
    assert reason == "VERIFY_UNAVAILABLE"
    assert all(r["check_type"] == "command" for r in results)


def test_result_type_matches_the_request_and_reaches_the_receipt():
    contract = _contract()
    gate = Gate(contract)
    request = build_transaction_request(contract)
    authorization = build_authorization_decision(request, policy_ref="contract:test")
    accepted, results, reason = gate.verify_completion("succeeded", lambda c: True)
    receipt = gate.issue_receipt("succeeded", accepted, results, reason,
                                 request=request, authorization=authorization)
    wanted = {r["check_id"]: r["check_type"] for r in request["verification_requirements"]}
    got = {r["check_id"]: r.get("check_type") for r in receipt["verification_results"]}
    assert got == wanted and set(got) == {"check-1", "check-2"}
