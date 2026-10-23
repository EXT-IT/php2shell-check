#!/usr/bin/env python3
"""Compare the vulnerability data of php2shell-check.sh and php2shell-check.ps1.

Two files carrying the same table is the one thing in this repository that
cannot be tested by running either of them: a Linux run never touches the
PowerShell table, a Windows run never touches the shell one. So the next fix
gets entered in one file, the other keeps the old number, and both pass their
own tests while giving different verdicts for the same PHP.

This parses both files textually -- no shell, no PowerShell needed -- and
fails with a diff when they drift. Run it from the repository root:

    python3 tests/data_parity.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SH = ROOT / "php2shell-check.sh"
PS = ROOT / "php2shell-check.ps1"


def fail(message: str) -> None:
    print(f"  FAIL  {message}")
    fail.count += 1  # type: ignore[attr-defined]


fail.count = 0  # type: ignore[attr-defined]


def ok(message: str) -> None:
    print(f"  ok    {message}")


def read(path: Path) -> str:
    if not path.is_file():
        print(f"data_parity: {path} not found", file=sys.stderr)
        raise SystemExit(2)
    return path.read_text(encoding="utf-8")


def sh_function_body(text: str, name: str) -> str:
    """The body of a shell function, from its opening brace to the closing one."""
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{(.*?)^\}}", text, re.S | re.M)
    if not match:
        print(f"data_parity: function {name} not found in php2shell-check.sh", file=sys.stderr)
        raise SystemExit(2)
    return match.group(1)


def sh_upstream_fixed(text: str) -> tuple[dict[str, str], list[str]]:
    body = sh_function_body(text, "_p2s_upstream_fixed")
    fixed: dict[str, str] = {}
    no_fix: list[str] = []
    for line in body.splitlines():
        line = line.split("#", 1)[0].strip()
        branch_match = re.match(r"^([0-9.*|]+)\)\s*echo\s+([0-9][0-9a-zA-Z.]*)\s*;;", line)
        if branch_match:
            fixed[branch_match.group(1)] = branch_match.group(2)
            continue
        none_match = re.match(r"^([0-9.*|]+)\)\s*echo\s+none\s*;;", line)
        if none_match:
            no_fix.extend(none_match.group(1).split("|"))
    return fixed, no_fix


def sh_frozen(text: str) -> list[str]:
    match = re.search(r"^_p2s_frozen_versions='([^']*)'", text, re.M)
    if not match:
        print("data_parity: _p2s_frozen_versions not found", file=sys.stderr)
        raise SystemExit(2)
    return match.group(1).split()


def sh_scalar(text: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}='([^']*)'", text, re.M)
    return match.group(1) if match else ""


def ps_hashtable(text: str, name: str) -> dict[str, str]:
    match = re.search(rf"\${re.escape(name)}\s*=\s*@\{{(.*?)\}}", text, re.S)
    if not match:
        print(f"data_parity: ${name} not found in php2shell-check.ps1", file=sys.stderr)
        raise SystemExit(2)
    out: dict[str, str] = {}
    for key, value in re.findall(r"'([^']+)'\s*=\s*'([^']+)'", match.group(1)):
        out[key] = value
    return out


def ps_array(text: str, name: str) -> list[str]:
    match = re.search(rf"\${re.escape(name)}\s*=\s*@\((.*?)\)", text, re.S)
    if not match:
        print(f"data_parity: ${name} not found in php2shell-check.ps1", file=sys.stderr)
        raise SystemExit(2)
    return re.findall(r"'([^']+)'", match.group(1))


def ps_scalar(text: str, name: str) -> str:
    match = re.search(rf"\${re.escape(name)}\s*=\s*'([^']*)'", text, re.M)
    return match.group(1) if match else ""


def compare(label: str, left, right) -> None:
    if left == right:
        ok(f"{label} match")
        return
    fail(f"{label} differ")
    print(f"        php2shell-check.sh : {left}")
    print(f"        php2shell-check.ps1: {right}")


def main() -> int:
    sh_text = read(SH)
    ps_text = read(PS)

    print("Vulnerability data parity between the shell and the PowerShell edition")

    sh_fixed, sh_no_fix = sh_upstream_fixed(sh_text)
    ps_fixed = ps_hashtable(ps_text, "script:P2sUpstreamFixed")
    compare("first fixed release per branch", sh_fixed, ps_fixed)

    ps_no_fix = ps_array(ps_text, "script:P2sNoFixBranchPatterns")
    compare("branches without a released fix", sorted(sh_no_fix), sorted(ps_no_fix))

    compare("frozen upstream versions", sorted(sh_frozen(sh_text)),
            sorted(ps_array(ps_text, "script:P2sFrozenVersions")))

    compare("data date", sh_scalar(sh_text, "P2S_DATA_DATE"),
            ps_scalar(ps_text, "script:P2sDataDate"))
    compare("advisory id", sh_scalar(sh_text, "P2S_ADVISORY"),
            ps_scalar(ps_text, "script:P2sAdvisory"))
    compare("advisory url", sh_scalar(sh_text, "P2S_ADVISORY_URL"),
            ps_scalar(ps_text, "script:P2sAdvisoryUrl"))
    compare("repository url", sh_scalar(sh_text, "P2S_REPO_URL"),
            ps_scalar(ps_text, "script:P2sRepoUrl"))
    compare("background url", sh_scalar(sh_text, "P2S_INFO_URL"),
            ps_scalar(ps_text, "script:P2sInfoUrl"))

    # The script version may differ while one edition is ahead, but a release
    # ships both, so a mismatch is worth printing without failing the run.
    sh_version = sh_scalar(sh_text, "P2S_SCRIPT_VERSION")
    ps_version = ps_scalar(ps_text, "script:P2sScriptVersion")
    if sh_version != ps_version:
        print(f"  note  script versions differ: sh {sh_version}, ps1 {ps_version}")
    else:
        ok(f"script version {sh_version} in both")

    # The README prints the data date twice, in a badge and in the fix table.
    # Both went stale in v1.6.0 while the scripts moved on, which is exactly
    # the drift this file exists to catch.
    readme = read(ROOT / "README.md")
    sh_date = sh_scalar(sh_text, "P2S_DATA_DATE")
    badge = re.search(r"vulnerability%20data-(\d{4})--(\d{2})--(\d{2})-", readme)
    badge_date = "-".join(badge.groups()) if badge else ""
    compare("data date in the README badge", sh_date, badge_date)
    if f"existed on {sh_date}" in readme:
        ok("data date in the fix table match")
    else:
        fail(f"the README fix table does not say \"existed on {sh_date}\"")

    # The PowerShell edition has no distribution table on purpose: the php.net
    # Windows builds carry real upstream versions. Guard that reasoning, so a
    # later copy-paste does not smuggle a Debian table into the Windows file.
    if re.search(r"P2sDistroFixed|deb13u1|0ubuntu0", ps_text):
        fail("the PowerShell edition carries distribution package data, which it must not: "
             "Windows builds are judged by upstream version")
    else:
        ok("the PowerShell edition carries no distribution table")

    print()
    if fail.count:  # type: ignore[attr-defined]
        print(f"{fail.count} mismatch(es)")  # type: ignore[attr-defined]
        return 1
    print("data in both editions is identical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
