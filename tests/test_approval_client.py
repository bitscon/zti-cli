"""The gate daemon's side of operator approval (hooks/claude-code/gated.py),
driven against a stand-in plane.

When the gate refuses a write to a path the contract is silent about, it asks
the plane whether the operator has approved that exact action. That question
can only ever turn this gate's own refusal into an allow, never the reverse,
and only on an explicit "approved". Everything else (pending, denied, a value
this client does not recognise, an unhashable value, a plane that is down)
leaves the refusal standing. A failed consult re-pulls the contract, and a
malformed policy reply never escapes into the decision path.

The plane half of approval (storing, deciding and spending approvals) ships
with the ZTI Core plane and is tested there.
"""

from pathlib import Path

import pytest

import gated

CONTRACT = {"work_id": "lease-demo", "allowed_paths": ["src/**"],
            "forbidden_paths": ["secrets/**"], "required_checks": []}
ETAG = "etag-1"


class FakePlane:
    """Answers the daemon's plane calls. `escalation` is the body returned for
    an approval consult, or an exception to raise; `policy` likewise for a
    contract re-pull after startup."""

    def __init__(self, escalation=None, policy=None):
        self.escalation = escalation
        self.policy = policy
        self.calls = []
        self.policy_pulls = 0

    def api(self, path, body=None, key=None, enroll=False):
        self.calls.append((path, body))
        if path == "/v1/gates/register":
            return {"gate_id": "g1", "api_key": "k1", "hook_secret": "s"}
        if path.endswith("/policy"):
            self.policy_pulls += 1
            if self.policy_pulls == 1:
                return {"contract": CONTRACT, "etag": ETAG}
            if isinstance(self.policy, Exception):
                raise self.policy
            return self.policy if self.policy is not None else {"contract": CONTRACT,
                                                                "etag": ETAG}
        if path.endswith("/escalations"):
            if isinstance(self.escalation, Exception):
                raise self.escalation
            return self.escalation
        return {}

    def consults(self):
        return [b for p, b in self.calls if p.endswith("/escalations")]

    def shipped(self):
        return [b for p, b in self.calls if p.endswith("/events")]


@pytest.fixture
def make_daemon(tmp_path, monkeypatch):
    def _make(**kw):
        plane = FakePlane(**kw)
        monkeypatch.setattr(gated, "api", plane.api)
        monkeypatch.setenv("ZTI_GATE_SESSION_FILE", str(tmp_path / ".zti" / "gated.session"))
        return gated.Daemon(tmp_path, "demo"), plane
    return _make


def _write(daemon, rel_path, tool="Write"):
    return daemon.evaluate(tool, {"file_path": str(Path(daemon.repo_root) / rel_path)})


# --- only an explicit "approved" releases ------------------------------------

def test_an_approved_state_releases_the_action_once(make_daemon):
    daemon, plane = make_daemon(escalation={"state": "approved", "escalation_id": "e1"})
    _, d = _write(daemon, "docs/x.md")
    assert d.decision == "allow" and d.reason_code == "APPROVAL_RELEASED"
    consult = plane.consults()[0]
    assert consult["policy_etag"] == ETAG
    assert consult["reason_code"] == "OUT_OF_SCOPE"


def test_a_pending_state_is_not_an_allow(make_daemon):
    daemon, _ = make_daemon(escalation={"state": "pending", "escalation_id": "e1"})
    _, d = _write(daemon, "docs/x.md")
    assert d.decision != "allow"
    assert "awaiting operator approval" in d.detail


def test_a_denied_state_is_not_an_allow(make_daemon):
    daemon, _ = make_daemon(escalation={"state": "denied", "escalation_id": "e1"})
    _, d = _write(daemon, "docs/x.md")
    assert d.decision != "allow"
    assert "operator denied" in d.detail


@pytest.mark.parametrize("state", ["APPROVED", "approved ", "released", "allow",
                                   "yes", "", None, 1, True])
def test_an_unrecognised_release_state_is_not_an_allow(make_daemon, state):
    daemon, _ = make_daemon(escalation={"state": state, "escalation_id": "e1"})
    _, d = _write(daemon, "docs/x.md")
    assert d.decision != "allow", state
    assert "not released" in d.detail


@pytest.mark.parametrize("state", [{}, [], {"approved": True}, ["approved"]])
def test_an_unhashable_release_state_is_still_a_deny(make_daemon, state):
    daemon, plane = make_daemon(escalation={"state": state, "escalation_id": "e1"})
    _, d = _write(daemon, "docs/x.md")            # must not raise
    assert d.decision != "allow"
    assert plane.shipped(), "the denial never reached the plane"


@pytest.mark.parametrize("failure", [gated.PlaneError("plane unreachable at stub"),
                                     ValueError("malformed body")])
def test_a_plane_that_fails_leaves_the_gate_denying(make_daemon, failure):
    daemon, plane = make_daemon(escalation=failure)
    _, d = _write(daemon, "docs/x.md")
    assert d.decision != "allow"
    assert "approval unavailable" in d.detail
    assert plane.policy_pulls == 2                # the failed consult re-pulled the contract


def test_a_non_dict_answer_is_a_deny(make_daemon):
    daemon, _ = make_daemon(escalation=["approved"])
    _, d = _write(daemon, "docs/x.md")
    assert d.decision != "allow"


# --- what is and is not put to the operator ----------------------------------

def test_forbidden_and_in_scope_writes_never_consult(make_daemon):
    daemon, plane = make_daemon(escalation={"state": "approved", "escalation_id": "e1"})
    _, forbidden = _write(daemon, "secrets/key")
    _, allowed = _write(daemon, "src/app.py")
    assert forbidden.decision != "allow"          # the operator already answered
    assert allowed.decision == "allow"
    assert plane.consults() == []


def test_one_file_is_presented_the_same_whichever_tool_wrote_it(make_daemon):
    """The operator approves or denies a FILE, not the tool that asked."""
    daemon, plane = make_daemon(escalation={"state": "pending", "escalation_id": "e1"})
    for tool in ("Write", "Edit", "NotebookEdit"):
        _write(daemon, "docs/x.md", tool=tool)
    actions = [c["action"] for c in plane.consults()]
    assert len(actions) == 3
    assert all(a == actions[0] for a in actions)
    assert actions[0]["command"] == "write docs/x.md"


def test_escalation_action_leaves_commands_untouched():
    action = {"type": "exec", "path": "", "command": "make deploy"}
    assert gated._escalation_action(action) == action
    write = {"type": "write", "path": "a/b", "command": "Edit a/b"}
    assert gated._escalation_action(write)["command"] == "write a/b"
    assert write["command"] == "Edit a/b"         # the caller's dict is not mutated


# --- the contract re-pull after a failed consult -----------------------------

def test_a_policy_body_with_no_etag_does_not_escape_the_refresh(make_daemon):
    daemon, plane = make_daemon(escalation=gated.PlaneError("409 POLICY_STALE"),
                                policy={"contract": dict(CONTRACT, allowed_paths=["**"])})
    _, d = _write(daemon, "docs/x.md")            # must not raise
    assert d.decision != "allow"
    assert daemon.policy_etag == ETAG             # nothing half-applied
    assert daemon.contract.allowed_paths == ["src/**"]
    assert plane.shipped(), "the denial never reached the plane"


@pytest.mark.parametrize("policy", [{}, {"etag": "e2"}, {"contract": "x", "etag": "e2"},
                                    gated.PlaneError("plane unreachable")])
def test_a_failed_refresh_keeps_enforcing_the_held_contract(make_daemon, policy):
    daemon, _ = make_daemon(escalation=gated.PlaneError("down"), policy=policy)
    _, d = _write(daemon, "docs/x.md")
    assert d.decision != "allow"
    assert daemon.policy_etag == ETAG and daemon.contract.allowed_paths == ["src/**"]


def test_a_refresh_with_a_new_etag_rebinds_the_same_gate(make_daemon):
    newer = dict(CONTRACT, forbidden_paths=["secrets/**", "docs/**"])
    daemon, _ = make_daemon(escalation=gated.PlaneError("409 POLICY_STALE"),
                            policy={"contract": newer, "etag": "etag-2"})
    gate_before = daemon.gate
    _write(daemon, "docs/x.md")
    assert daemon.policy_etag == "etag-2"
    assert daemon.gate is gate_before             # audit history kept, not replaced
    assert daemon.gate.contract.forbidden_paths == ["secrets/**", "docs/**"]
    _, again = _write(daemon, "docs/x.md")
    assert again.reason_code == "FORBIDDEN_PATH_WRITE"
