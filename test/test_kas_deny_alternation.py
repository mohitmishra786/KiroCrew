"""A ``deniedCommands`` entry with group alternation reaches KAS as one deny per branch.

kiro-cli anchors ``(touch|mkdir) .*`` at both ends, so it denies ``mkdir d``; the
KAS engine splits it into ``touch *`` and ``mkdir *`` when it reads an agent
profile itself. The projection sends the same globs, since the gate cannot read
alternation and would otherwise let ``mkdir d`` run.
"""

from __future__ import annotations

from typing import Any

import pytest

from kiro_crew.acp import kas_agents
from kiro_crew.acp.kas_permissions import shell_deny_globs, tools_settings_to_permissions
from kiro_crew.acp.kas_spec_denies import uncarried_denied_commands


def _spec(denied: list[str], **over: Any) -> dict[str, Any]:
    return {
        "name": "a",
        "prompt": "p",
        "tools": ["*"],
        "includeMcpJson": False,
        "toolsSettings": {"shell": {"deniedCommands": denied}},
        **over,
    }


def _shell_globs(denied: list[str]) -> set[str]:
    out = kas_agents.to_client_custom_agent("a", _spec(denied), "p")
    return shell_deny_globs(out.get("permissions"))


def _named(denied: list[str]) -> list[str]:
    keys = kas_agents.spec_keys_without_carrier(_spec(denied), translates_tools_settings=True)
    return [k for k in keys if "deniedCommand" in k]


@pytest.mark.parametrize(
    ("regex", "globs"),
    [
        ("(touch|mkdir) .*", {"touch *", "mkdir *"}),
        ("(rm|shred) .*", {"rm *", "shred *"}),
        ("^(rm|shred) .*$", {"rm *", "shred *"}),
        (r"\A(?:rm|shred) .*\z", {"rm *", "shred *"}),
        ("(git|hg) (push|pull).*", {"git push*", "git pull*", "hg push*", "hg pull*"}),
        ("rm(| -rf) .*", {"rm *", "rm -rf *"}),
    ],
)
def test_a_group_alternation_reaches_kas_as_one_deny_per_branch(regex: str, globs: set[str]):
    assert globs <= _shell_globs([regex])
    assert _named([regex]) == []
    settings = {"shell": {"deniedCommands": [regex]}}
    block, lost = tools_settings_to_permissions(settings)
    assert lost == []
    assert uncarried_denied_commands(settings, block) == []


@pytest.mark.parametrize(
    ("regex", "globs"),
    [
        ("touch .*", {"touch *"}),
        (r"rm \.env", {"rm .env"}),
        (r"echo \(a\|b\) .*", {"echo (a|b) *"}),
    ],
)
def test_an_entry_with_no_group_travels_as_before(regex: str, globs: set[str]):
    assert _shell_globs([regex]) == globs
    assert _named([regex]) == []


@pytest.mark.parametrize(
    "regex",
    [
        "rm .*|shred .*",  # top level: Rust reads it as "starts with rm or ends with shred"
        "(rm|shred)+ .*",  # a repeated group
        "((rm|shred)) .*",  # a nested group
        "(?i:rm|shred) .*",  # a flag group
        "([r]m|shred) .*",  # a class inside the group
        "(rm|shred .*",  # never closed
    ],
)
def test_an_alternation_the_split_cannot_read_exactly_is_still_named(regex: str):
    assert _shell_globs([regex]) == set()
    assert len(_named([regex])) == 1


def test_a_class_deny_stays_held_by_the_gate():
    settings = {"shell": {"deniedCommands": ["[rm]m .*"]}}
    block, _ = tools_settings_to_permissions(settings)
    assert uncarried_denied_commands(settings, block) == ["[rm]m .*"]


def test_a_command_no_branch_names_is_not_denied():
    globs = _shell_globs(["(touch|mkdir) .*"])
    assert not any(g.split()[0] in {"ls", "rm", "cat"} for g in globs)


def test_the_split_is_bounded():
    from kiro_crew.acp.kas_deny_alternatives import MAX_ALTERNATIVES, deny_alternatives

    wide = "(a|b)" * 7  # 128 combinations
    assert 2**7 > MAX_ALTERNATIVES
    assert deny_alternatives(wide) == [wide]
    assert len(deny_alternatives("(a|b)" * 6)) == 64


def test_a_split_deny_lifts_no_shell_grant():
    """The deny now travels, but Crew still cannot read it, so a shell grant beside
    it stays at the prompt exactly as before: nothing new runs unasked."""
    from kiro_crew.acp.kas_permissions import CREW_SPEC_DENIES_KEY

    out = kas_agents.to_client_custom_agent(
        "a", _spec(["(rm|shred) .*"], allowedTools=["shell"]), "p"
    )
    assert "execute_bash" not in out.get("_crewAnsweredBuiltins", ())
    assert CREW_SPEC_DENIES_KEY not in out


def test_a_bot_worker_holds_its_shell_only_for_an_unsplit_deny():
    """The worker's hold is for an entry nobody enforces; a split one KAS enforces."""
    from kiro_crew import mate_spec_policy

    spec = {"toolsSettings": {"shell": {"deniedCommands": ["(rm|shred) .*", "a.*|b.*"]}}}
    assert mate_spec_policy.unjudged_denies(spec) == ["a.*|b.*"]
