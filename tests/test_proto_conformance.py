"""ADR-0010 — full ZTIP execution-receipt conformance + the request→receipt chain.

The library half of the upstream conformance suite (the control-plane ingest
and evidence-pack halves live in the product tree — no plane ships here).

Two layers, deliberately separate:

* SCHEMA VALIDATION against the open spec's actual `schemas/*.schema.json`
  (the authority). The ztip PACKAGE ships only the runtime module, so these
  run where the ztip repo checkout is a sibling (and jsonschema is installed)
  and skip loudly elsewhere.
* STRUCTURAL CONFORMANCE PINS that duplicate the schema's load-bearing facts
  (required fields, status enum, reason-code value set) with no external
  files — these run everywhere, including CI, so a regression cannot merge
  past them even where the schema files are absent.
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ztip.chain import verify_bundle
from ztip.hashing import envelope_hash, verify_envelope_hash
from ztipgate.gate import (Contract, Gate, build_authorization_decision,
                           build_transaction_request)

TREE_A = "a" * 40


# ── helpers ──────────────────────────────────────────────────────────────────

def _schema_dir():
    for up in Path(__file__).resolve().parents:
        cand = up / "ztip" / "schemas"
        if (cand / "execution-receipt.schema.json").exists():
            return cand
    return None


requires_schemas = pytest.mark.skipif(
    _schema_dir() is None,
    reason="ztip schema files absent (the ztip package ships only the runtime "
           "module) — jsonschema validation runs where the ztip repo checkout "
           "is a sibling; the structural pins in this file run everywhere")


def _validator(schema_name):
    jsonschema = pytest.importorskip("jsonschema")
    from referencing import Registry, Resource
    schema_dir = _schema_dir()
    resources = []
    for f in schema_dir.glob("*.schema.json"):
        doc = json.loads(f.read_text())
        resources.append((doc["$id"], Resource.from_contents(doc)))
    registry = Registry().with_resources(resources)
    schema = json.loads((schema_dir / schema_name).read_text())
    return jsonschema.Draft202012Validator(
        schema, registry=registry, format_checker=jsonschema.FormatChecker())


def _errors(envelope, schema_name):
    return [f"{'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message}"
            for e in _validator(schema_name).iter_errors(envelope)]


def _chain_mint(passing=True, claimed="succeeded", work_id="w-conf", checks=None,
                actions=(), created_at=None):
    """A full chain mint: (receipt, request, authorization), the `zti receipt` shape."""
    contract = Contract(work_id=work_id, allowed_paths=["src/**"],
                        forbidden_paths=["db/**"],
                        required_checks=checks if checks is not None else ["true"])
    request = build_transaction_request(
        contract, repo="demo/repo", gate_id="g1",
        parameters={"repo": "demo/repo", "tree_hash": TREE_A},
        created_at=created_at)
    authorization = build_authorization_decision(
        request, policy_ref="zti-core:gates/g1/policy@etag1234", gate_id="g1")
    gate = Gate(contract)
    for action in actions:
        gate.check_action(action)
    accepted, results, reason = gate.verify_completion(claimed, lambda c: passing)
    receipt = gate.issue_receipt(claimed, accepted, results, reason,
                                 request=request, authorization=authorization)
    return receipt, request, authorization


def _v1_receipt(work_id="w-v1", status="blocked"):
    """A format-1 receipt, exactly the shape `issue_receipt` minted before
    ADR-0010, hash-sealed with the unchanged hashing rule. The compatibility
    contract under test: these must keep verifying forever."""
    envelope = {
        "ztap_version": "1.0-draft",
        "envelope_type": "execution_receipt",
        "transaction_id": work_id,
        "receipt_id": f"rcpt-{work_id}",
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "agent_claimed_status": "succeeded",
        "reason_codes": [] if status == "succeeded" else ["COMPLETION_UNVERIFIED"],
        "actions_attempted": [],
        "actions_completed": [],
        "actions_blocked": [],
        "verification_results": [{"check": "true", "passed": status == "succeeded",
                                  "verifier": "gate-independent"}],
        "verification_authority": "independent-gate",
        "audit_chain_head": None,
        "integrity": {"canonicalization": "RFC8785-JCS", "hash_algorithm": "SHA-256"},
    }
    envelope["integrity"]["hash_value"] = envelope_hash(envelope)
    return envelope


# ── schema validation against the open spec (the authority) ──────────────────

@requires_schemas
def test_chain_mint_validates_against_the_open_schemas():
    receipt, request, authorization = _chain_mint(passing=True)
    assert _errors(request, "transaction-request.schema.json") == []
    assert _errors(authorization, "authorization-decision.schema.json") == []
    assert _errors(receipt, "execution-receipt.schema.json") == []
    # And through the top-level envelope oneOf — each is exactly one known type.
    for env in (request, authorization, receipt):
        assert _errors(env, "ztip-envelope.schema.json") == []


@requires_schemas
def test_refused_mint_validates_too():
    receipt, _, _ = _chain_mint(
        passing=False,
        actions=[{"type": "write", "path": "db/prod.db", "command": "w"}])
    assert _errors(receipt, "execution-receipt.schema.json") == []


@requires_schemas
def test_v1_receipt_is_not_schema_conformant():
    # Teeth: the old lean shape must FAIL validation — if it passed, this
    # suite would prove nothing about the new fields.
    assert _errors(_v1_receipt(), "execution-receipt.schema.json") != []


@requires_schemas
def test_no_checks_contract_yields_nonconformant_request_by_design():
    # The spec requires verification declared before execution (minItems 1).
    # A contract with no checks produces an honestly-invalid request — the
    # same degenerate case the gate refuses with NO_CHECKS_DEFINED.
    contract = Contract(work_id="w-none", allowed_paths=["**"], required_checks=[])
    request = build_transaction_request(contract, repo="demo/repo", gate_id="g1")
    assert any("verification_requirements" in e
               for e in _errors(request, "transaction-request.schema.json"))


# ── structural conformance pins (run everywhere, incl. CI) ───────────────────

RECEIPT_REQUIRED_FIELDS = {
    # execution-receipt.schema.json `required` + the common envelope's.
    "ztap_version", "envelope_type", "transaction_id", "integrity",
    "receipt_id", "request_hash", "authorization_decision_ref",
    "source_actor", "target_actor", "control_plane",
    "started_at", "completed_at", "status", "reason_codes",
    "actions_attempted", "actions_completed", "verification_results",
    "atomicity_result",
}

SPEC_STATUS_ENUM = {"succeeded", "failed", "rejected", "cancelled", "expired",
                    "timed_out"}

SPEC_REASON_ENUM = {
    "SCHEMA_INVALID", "ROLE_INVALID", "ACTOR_UNREGISTERED", "AUTHORITY_MISSING",
    "POLICY_DENIED", "APPROVAL_REPLAYED", "RISK_LEVEL_ESCALATED",
    "CAPABILITY_MISSING", "TARGET_REJECTED", "ACTION_FAILED", "VERIFY_FAILED",
    "COMPLETION_UNVERIFIED", "VERIFY_UNAVAILABLE", "TIMEOUT", "EXPIRED",
    "CANCELLED", "INTEGRITY_FAILED", "EVIDENCE_MISSING",
    "PARTIAL_STATE_BLOCKED", "REGISTRY_INCONSISTENT",
}

NAMESPACED = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+"
    r"/[A-Za-z0-9][A-Za-z0-9._-]*$")


def test_chain_receipt_carries_every_spec_required_field():
    receipt, _, _ = _chain_mint(passing=True)
    missing = RECEIPT_REQUIRED_FIELDS - receipt.keys()
    assert missing == set()
    assert receipt["ztap_version"] == "1.0-draft"   # the spec const — never renamed
    assert receipt["zti_receipt_format"] == 2
    for role_block in ("source_actor", "target_actor", "control_plane"):
        actor = receipt[role_block]
        assert {"actor_id", "role", "organization_id", "registration_ref"} <= actor.keys()


def test_status_uses_spec_vocabulary_only():
    ok, _, _ = _chain_mint(passing=True)
    refused, _, _ = _chain_mint(passing=False)
    assert ok["status"] == "succeeded"
    assert refused["status"] == "failed"            # never the format-1 "blocked"
    assert ok["status"] in SPEC_STATUS_ENUM and refused["status"] in SPEC_STATUS_ENUM


def test_reason_codes_stay_inside_the_spec_value_set():
    receipt, _, _ = _chain_mint(
        passing=False,
        actions=[{"type": "write", "path": "db/prod.db", "command": "w"},
                 {"type": "write", "path": "../escape", "command": "w"}])
    assert receipt["reason_codes"]                   # refused → minItems 1
    for code in receipt["reason_codes"]:
        assert code in SPEC_REASON_ENUM or NAMESPACED.fullmatch(code), code
    assert "zti.gate/FORBIDDEN_PATH_WRITE" in receipt["reason_codes"]
    assert "zti.gate/OUT_OF_SCOPE" in receipt["reason_codes"]


def test_completion_reason_mapping_is_the_spec_distinction():
    # Check ran and failed → VERIFY_FAILED.
    failed_check, _, _ = _chain_mint(passing=False, claimed="succeeded")
    assert "VERIFY_FAILED" in failed_check["reason_codes"]
    assert "ACTION_FAILED" not in failed_check["reason_codes"]
    # Executor itself did not claim success (checks pass) → ACTION_FAILED.
    no_claim, _, _ = _chain_mint(passing=True, claimed="failed")
    assert "ACTION_FAILED" in no_claim["reason_codes"]
    assert "VERIFY_FAILED" not in no_claim["reason_codes"]
    # Both true → both recorded.
    both, _, _ = _chain_mint(passing=False, claimed="failed")
    assert {"VERIFY_FAILED", "ACTION_FAILED"} <= set(both["reason_codes"])
    # No real checks → the namespaced gate code, nothing else about completion.
    none, _, _ = _chain_mint(checks=[])
    assert "zti.gate/NO_CHECKS_DEFINED" in none["reason_codes"]


def test_atomicity_result_reflects_what_happened():
    ok, _, _ = _chain_mint(passing=True)
    assert ok["atomicity_result"] == {"mode_declared": "best_effort_allowed",
                                      "outcome": "full", "rollback_performed": False}
    # Refused with completed work → partial, with the spec-required description.
    partial, _, _ = _chain_mint(
        passing=False,
        actions=[{"type": "write", "path": "src/app.py", "command": "w"}])
    assert partial["atomicity_result"]["outcome"] == "partial"
    assert partial["atomicity_result"]["partial_state_description"] == {
        "actions_completed": 1, "actions_blocked": 0}
    # Refused with nothing completed → none.
    nothing, _, _ = _chain_mint(passing=False)
    assert nothing["atomicity_result"]["outcome"] == "none"


def test_verification_results_name_the_verifying_authority():
    receipt, _, _ = _chain_mint(passing=True)
    assert receipt["verification_results"], "expected at least one check result"
    for i, result in enumerate(receipt["verification_results"], start=1):
        # SPEC.md Recorded Results: the verifying authority is named — the gate
        # (the control_plane actor), not a bare label.
        assert result["verification_actor"] == receipt["control_plane"]["actor_id"] == "g1"
        assert result["verifier"] == "gate-independent"  # format-1 key kept
        assert result["check_id"] == f"check-{i}"


def test_the_gate_is_the_control_plane_workspace_is_source_and_target():
    receipt, request, authorization = _chain_mint(passing=True)
    assert receipt["control_plane"]["actor_id"] == "g1"
    assert receipt["source_actor"]["actor_id"] == receipt["target_actor"]["actor_id"] \
        == "workspace:demo/repo"
    assert receipt["control_plane"]["actor_id"] != receipt["target_actor"]["actor_id"]
    assert authorization["control_plane"]["actor_id"] == "g1"


def test_requested_capabilities_are_a_subset_of_the_target_claims():
    _, request, _ = _chain_mint(passing=True)
    target_claims = set(request["target_actor"]["capability_claims"])
    assert set(request["requested_action"]["required_capabilities"]) <= target_claims
    assert set(request["requested_capabilities"]) <= target_claims


def test_standalone_mint_is_also_conformant():
    contract = Contract(work_id="standalone-unit", allowed_paths=["**"],
                        required_checks=["true"])
    gate = Gate(contract)
    accepted, results, reason = gate.verify_completion("succeeded", lambda c: True)
    receipt = gate.issue_receipt("succeeded", accepted, results, reason)
    assert RECEIPT_REQUIRED_FIELDS - receipt.keys() == set()
    assert receipt["control_plane"]["registration_ref"] == "unregistered"
    if _schema_dir() is not None:
        assert _errors(receipt, "execution-receipt.schema.json") == []


def test_succeeded_receipt_with_blocked_actions_has_clean_reason_codes():
    receipt, _, _ = _chain_mint(
        passing=True,
        actions=[{"type": "write", "path": "db/prod.db", "command": "w"}])
    assert receipt["status"] == "succeeded"
    assert receipt["reason_codes"] == []
    assert any(b["reason_code"] == "FORBIDDEN_PATH_WRITE"
               for b in receipt["actions_blocked"])


def test_unavailable_verifier_resolves_verify_unavailable_not_a_crash():
    contract = Contract(work_id="unavail-unit", allowed_paths=["**"],
                        required_checks=["flaky"])
    gate = Gate(contract)

    def raising_runner(check):
        raise OSError("verifier binary not found")

    accepted, results, reason = gate.verify_completion("succeeded", raising_runner)
    assert accepted is False and reason == "VERIFY_UNAVAILABLE"
    receipt = gate.issue_receipt("succeeded", accepted, results, reason)
    assert receipt["status"] == "failed"
    assert "VERIFY_UNAVAILABLE" in receipt["reason_codes"]
    if _schema_dir() is not None:
        assert _errors(receipt, "execution-receipt.schema.json") == []


def test_half_chain_is_refused_at_mint():
    contract = Contract(work_id="w-half", allowed_paths=["**"], required_checks=["true"])
    request = build_transaction_request(contract, repo="demo/repo")
    gate = Gate(contract)
    accepted, results, reason = gate.verify_completion("succeeded", lambda c: True)
    with pytest.raises(ValueError):
        gate.issue_receipt("succeeded", accepted, results, reason, request=request)


def test_started_at_precedes_completed_at():
    receipt, _, _ = _chain_mint(passing=True)
    assert receipt["started_at"] <= receipt["completed_at"]  # ISO-8601 sorts


# ── the chain, proven with the open tool ─────────────────────────────────────

def test_open_ztip_verify_proves_the_chain():
    receipt, request, authorization = _chain_mint(passing=True)
    assert receipt["request_hash"] == envelope_hash(request)
    assert receipt["authorization_decision_ref"] == authorization["decision_id"]
    assert authorization["request_hash"] == envelope_hash(request)
    assert verify_bundle({"envelopes": [request, authorization, receipt]}) == []


def test_tampered_request_breaks_the_chain_even_resealed():
    receipt, request, authorization = _chain_mint(passing=True)
    tampered = json.loads(json.dumps(request))
    tampered["verification_requirements"] = []       # rewrite the declared checks
    tampered["integrity"]["hash_value"] = envelope_hash(tampered)  # re-seal
    findings = verify_bundle({"envelopes": [tampered, authorization, receipt]})
    assert any(f["code"] == "REQUEST_HASH_BROKEN" for f in findings)


def test_v1_receipt_still_hash_verifies():
    assert verify_envelope_hash(_v1_receipt()) is True
    # And rides in a bundle without chain findings — it carries no request_hash,
    # so no linkage is claimed or checked for it.
    assert verify_bundle({"envelopes": [_v1_receipt()]}) == []


# ── the import guard: a broken installed ztip must raise, not be swapped ─────

def test_broken_installed_ztip_raises_instead_of_silent_fallback(tmp_path):
    """Reproduction for the narrowed guard (ImportError → ModuleNotFoundError):
    a ztip that EXISTS but fails to import must propagate its error. Under the
    old `except ImportError`, this fake broken install fell through to the
    sibling-checkout walker, which silently imported a different ztip than the
    one that appeared to be installed."""
    fake = tmp_path / "ztip"
    fake.mkdir()
    (fake / "__init__.py").write_text("")
    (fake / "hashing.py").write_text(
        "raise ImportError('simulated broken ztip install')\n")
    repo_root = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [sys.executable, "-c", "import ztipgate.gate"],
        cwd=repo_root, capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": f"{tmp_path}{os.pathsep}{repo_root}"})
    assert proc.returncode != 0
    assert "simulated broken ztip install" in proc.stderr
