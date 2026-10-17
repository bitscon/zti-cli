"""The constant-true no-op check classifier (`is_noop_check`).

The classifier half of the upstream suite. The contract generator that also
uses it ships with the ZTI Core plane, so its half stays in the product tree.
`zti receipt` uses this classifier to warn, at mint, when a required check
verifies nothing.
"""

import pytest

from ztipgate.gate import is_noop_check


@pytest.mark.parametrize("cmd", [
    "true",
    ":",
    "/bin/true",
    "echo ok",
    'echo "pytest passed"',
    "printf done",
    "exit 0",
    "exit",
    "true && true",
    "true; echo ok",
    "  true  ",
    "",
    "   ",
    '""',
    # Constant-true by trailing neutralizer (wave-1 fix): `;`/`|`/`||` all
    # make the final element's exit the command's exit, so a final no-op
    # makes the whole check unconditionally pass.
    "pytest -q && npm run lint || true",
    "pytest | true",
    "pytest -q; true",
    "pytest || echo failed",
    "make test || :",
])
def test_constant_true_commands_classify_as_noop(cmd):
    assert is_noop_check(cmd) is True


@pytest.mark.parametrize("cmd", [
    "pytest -q",
    "npm test",
    "make test",
    "go test ./...",
    "false",                 # constant-FALSE can never green — not this class
    "exit 1",
    "true && pytest -q",     # one real sub-command makes the whole thing real
    "echo start; pytest -q",
    "sh -c 'true'",          # obfuscation — documented limit, conservatively real
    "command true",          # ditto — name indirection is not guessed at
    "bash run_tests.sh",     # file content unknown — never guessed at
    "truevalidate --all",    # prefix of a no-op name is not the no-op
    "pytest && true",        # `&&` preserves pytest's failure — genuinely real
    "false || pytest -q",    # final element is real
    "pytest || true && ruff check .",  # exit follows ruff — real
])
def test_real_commands_are_not_flagged(cmd):
    assert is_noop_check(cmd) is False


def test_non_string_input_fails_closed_as_noop():
    assert is_noop_check(None) is True
