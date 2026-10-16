"""The `zti` CLI against a stand-in plane (zticli/main.py).

The upstream CLI suite drives these behaviours against the real ZTI Core
plane, which does not ship here. This suite swaps the CLI's HTTP layer
(`zticli.main.Plane`) for an in-memory stand-in that answers the three calls
the CLI makes; git, the gate library, hashing and the checks are real.

Pins the client-side halves of:
  - zti:vac-gate (policy supremacy): when the plane publishes a policy for the
    repo, a DIVERGENT --contract is refused before anything runs or ships; a
    byte-for-byte restatement mints under the plane policy's etag.
  - zti:vac-gate (no-op lint): a constant-true required check mints, but the
    mint says out loud that it verifies nothing.
  - ADR-0013 (enforcement liveness): the plane's "stored but not verified"
    answer never prints SUCCEEDED, and a blocked verify names the plane's reason.
"""

import json
import subprocess

import pytest

import zticli.main as cli

CONTRACT = {"work_id": "lease-demo", "allowed_paths": ["**"],
            "forbidden_paths": [], "required_checks": ["git --version"]}
ETAG = "etag-published-1"


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A real git repo with one staged file; CLI commands run from inside it."""
    root = tmp_path / "governed"
    root.mkdir()
    for args in (["init", "-q"], ["config", "user.email", "t@t"],
                 ["config", "user.name", "t"]):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    (root / "app.py").write_text("print('v1')\n")
    subprocess.run(["git", "add", "-A"], cwd=root, check=True, capture_output=True)
    monkeypatch.chdir(root)
    monkeypatch.delenv("ZTI_PLANE_URL", raising=False)
    return root


def _plane(monkeypatch, policy=CONTRACT, ship=None, verify=None):
    """Install a stand-in plane. `policy=None` means no published policy (404).
    Returns the list of shipped bodies so a test can see what reached it."""
    shipped = []

    class FakePlane:
        def __init__(self, base_url, bearer):
            pass

        def get_policy(self, gate_id):
            if policy is None:
                return 404, {"detail": "no policy"}
            return 200, {"contract": policy, "etag": ETAG}

        def ship_receipt(self, gate_id, receipt, binding, request=None,
                         authorization=None):
            shipped.append({"receipt": receipt, "binding": binding,
                            "request": request, "authorization": authorization})
            if ship is not None:
                return ship(receipt)
            return 200, {"accepted": True, "verified": True,
                         "receipt_id": receipt["receipt_id"]}

        def verify_by_tree(self, tree):
            return 200, verify or {}

    monkeypatch.setattr(cli, "Plane", FakePlane)
    monkeypatch.setenv("ZTI_GATE_ID", "g1")
    monkeypatch.setenv("ZTI_GATE_KEY", "k")
    return shipped


# ── the operator's published policy outranks any local contract ──────────────

def test_contract_diverging_from_policy_refuses_to_mint(repo, monkeypatch, tmp_path, capsys):
    """An agent-supplied --contract that differs from the published policy must
    not mint at all: no checks run, nothing ships."""
    shipped = _plane(monkeypatch)
    weak = dict(CONTRACT, required_checks=["true"])
    contract_file = tmp_path / "weak.json"
    contract_file.write_text(json.dumps(weak))
    assert cli.main(["receipt", "--contract", str(contract_file)]) == cli.USAGE
    captured = capsys.readouterr()
    assert "diverges from the policy" in captured.err
    assert ETAG in captured.err
    assert "[PASS]" not in captured.out          # no check ran
    assert shipped == []                         # nothing reached the plane


def test_contract_matching_policy_mints_under_policy_etag(repo, monkeypatch, tmp_path, capsys):
    """A --contract that restates the published policy (key order irrelevant)
    is fine, and the mint is attributed to the plane policy, not to the file."""
    shipped = _plane(monkeypatch)
    contract_file = tmp_path / "same.json"
    contract_file.write_text(json.dumps(dict(reversed(list(CONTRACT.items())))))
    assert cli.main(["receipt", "--contract", str(contract_file)]) == cli.PASS
    assert "SUCCEEDED" in capsys.readouterr().out
    assert len(shipped) == 1
    refs = shipped[0]["authorization"]["policy_refs"]
    assert refs == [f"zti-core:gates/g1/policy@{ETAG}"]


def test_published_policy_is_used_over_a_local_contract_file(repo, monkeypatch, capsys):
    """.zti/contract.json is only the basis when the plane publishes nothing."""
    shipped = _plane(monkeypatch)
    (repo / ".zti").mkdir()
    (repo / ".zti" / "contract.json").write_text(
        json.dumps(dict(CONTRACT, required_checks=["true"])))
    assert cli.main(["receipt"]) == cli.PASS
    assert shipped[0]["authorization"]["policy_refs"][0].endswith(f"@{ETAG}")
    assert "git --version" in capsys.readouterr().out


def test_unpoliced_repo_keeps_the_local_contract_path(repo, monkeypatch, tmp_path, capsys):
    """No published policy (404): the local --contract is the honest basis and
    is attributed to its own content hash."""
    shipped = _plane(monkeypatch, policy=None)
    contract_file = tmp_path / "local.json"
    contract_file.write_text(json.dumps(CONTRACT))
    assert cli.main(["receipt", "--contract", str(contract_file)]) == cli.PASS
    assert shipped[0]["authorization"]["policy_refs"][0].startswith("contract:sha256:")


def test_no_contract_anywhere_fails_closed(repo, monkeypatch):
    _plane(monkeypatch, policy=None)
    assert cli.main(["receipt"]) == cli.USAGE


# ── the mint-time no-op lint ─────────────────────────────────────────────────

def test_mint_warns_on_constant_true_noop_check(repo, monkeypatch, capsys):
    """The published policy's check is literally `true`: the operator's right,
    so it mints, but the mint says out loud that it verifies nothing."""
    _plane(monkeypatch, policy=dict(CONTRACT, required_checks=["true"]))
    assert cli.main(["receipt"]) == cli.PASS
    err = capsys.readouterr().err
    assert "constant-true no-op" in err and "'true'" in err


def test_mint_does_not_warn_on_a_real_check(repo, monkeypatch, capsys):
    _plane(monkeypatch)
    assert cli.main(["receipt"]) == cli.PASS
    assert "no-op" not in capsys.readouterr().err


# ── ADR-0013: stored but not enforcement-verified ────────────────────────────

def test_receipt_unverified_third_outcome_fails_loud(repo, monkeypatch, capsys):
    """The plane's 200 {accepted, verified: false} must never print SUCCEEDED:
    that would assert exactly what the plane just denied."""
    def unverified(receipt):
        return 200, {"accepted": True, "verified": False,
                     "reason": "ENFORCEMENT_NOT_CONTINUOUS",
                     "receipt_id": receipt["receipt_id"]}
    _plane(monkeypatch, ship=unverified)
    assert cli.main(["receipt"]) == cli.RECEIPT_NOT_PASSED
    captured = capsys.readouterr()
    assert "NOT VERIFIED" in captured.err
    assert "ENFORCEMENT_NOT_CONTINUOUS" in captured.err
    assert "SUCCEEDED" not in captured.out
    assert "commit will pass" not in captured.out


def test_verify_blocked_line_names_the_planes_reason(repo, monkeypatch, capsys):
    _plane(monkeypatch, verify={"passing": False, "receipt_id": "rcpt-x",
                                "status": "succeeded",
                                "reason": "ENFORCEMENT_NOT_CONTINUOUS"})
    assert cli.main(["verify", "--staged"]) == cli.RECEIPT_NOT_PASSED
    err = capsys.readouterr().err
    assert "(ENFORCEMENT_NOT_CONTINUOUS)" in err
    assert "Address ENFORCEMENT_NOT_CONTINUOUS" in err
    assert "Fix the work" not in err


def test_verify_blocked_line_without_a_reason_keeps_the_old_advice(repo, monkeypatch, capsys):
    _plane(monkeypatch, verify={"passing": False, "receipt_id": "rcpt-x",
                                "status": "blocked"})
    assert cli.main(["verify", "--staged"]) == cli.RECEIPT_NOT_PASSED
    assert "Fix the work" in capsys.readouterr().err


# ── ADR-0016 through the CLI entry point ─────────────────────────────────────

def test_receipt_refuses_a_plaintext_off_box_plane_before_any_request(repo, monkeypatch, capsys):
    shipped = _plane(monkeypatch)
    monkeypatch.setenv("ZTI_PLANE_URL", "http://10.0.0.5:8100")
    monkeypatch.delenv("ZTI_ALLOW_INSECURE_HTTP", raising=False)
    assert cli.main(["receipt"]) == cli.USAGE
    assert "plaintext" in capsys.readouterr().err
    assert shipped == []
