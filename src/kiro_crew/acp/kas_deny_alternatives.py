"""A ``deniedCommands`` entry with group alternation, as the regexes it is the union of.

kiro-cli anchors an entry at both ends, so ``(touch|mkdir) .*`` denies exactly
what ``touch .*`` and ``mkdir .*`` deny together. KAS has no alternation in a
shell glob, and the engine itself splits such an entry into one glob per branch
(``touch *, mkdir *``) when it reads an agent profile. The KAS projection does the
same here, so the deny travels instead of being dropped.

Only a group the split reads exactly is split: ``( )`` or ``(?: )``, holding no
other group, no class and no repeat after it. Every other entry, including a
top-level ``a|b`` (which the Rust anchoring reads as "starts with ``a`` or ends
with ``b``"), comes back whole, so the caller treats it exactly as before.

A LEAF on purpose: stdlib only, so ``kas_permissions`` imports it.
"""

from __future__ import annotations

#: Most regexes one entry is split into, like ``kas_permissions._MAX_PATTERNS_PER_RULE``.
#: Past it the entry comes back whole and is reported as before.
MAX_ALTERNATIVES = 64

#: What may follow a group and repeat it; such a group is not split.
_REPEATS = frozenset("*+?{")


def deny_alternatives(pattern: str) -> list[str]:
    """The regexes *pattern* is the union of, one per combination of group branches.

    ``[pattern]`` when it has no group the split reads exactly (module docstring)."""
    pieces: list[list[str]] = [[""]]
    i = 0
    split = False
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            pieces[-1] = [p + pattern[i : i + 2] for p in pieces[-1]]
            i += 2
        elif ch in "[|)":
            return [pattern]
        elif ch == "(":
            start = i + 3 if pattern.startswith("(?:", i) else i + 1
            if pattern.startswith("(?", i) and start == i + 1:
                return [pattern]
            branches, end = _group_branches(pattern, start)
            if branches is None or pattern[end + 1 : end + 2] in _REPEATS:
                return [pattern]
            pieces.append(branches)
            pieces.append([""])
            split = True
            i = end + 1
        else:
            pieces[-1] = [p + ch for p in pieces[-1]]
            i += 1
    if not split:
        return [pattern]
    out = [""]
    for choices in pieces:
        out = [head + tail for head in out for tail in choices]
        if len(out) > MAX_ALTERNATIVES:
            return [pattern]
    return list(dict.fromkeys(out))


def _group_branches(pattern: str, start: int) -> tuple[list[str] | None, int]:
    """The branches of the group whose body starts at *start*, and the index of its
    ``)``; ``None`` for a group holding a group or a class, or one never closed."""
    branches = [""]
    i = start
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            branches[-1] += pattern[i : i + 2]
            i += 2
        elif ch in "([":
            return None, i
        elif ch == "|":
            branches.append("")
            i += 1
        elif ch == ")":
            return branches, i
        else:
            branches[-1] += ch
            i += 1
    return None, i
