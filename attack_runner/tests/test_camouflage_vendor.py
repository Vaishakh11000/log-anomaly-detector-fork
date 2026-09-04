"""
The vendored camouflage.py is kept byte-identical to the original.

CLAUDE.md section 2d requires the Kali box to apply the *identical* camouflage
transforms as the synthetic track, "one source of truth". attack_runner cannot
import logdet_eval (it is not on the Kali box), so it vendors a copy -- and a
copy silently drifting from the original would break exactly the comparability
the section demands. This test fails on any drift, which is what keeps "one
source of truth" true across the copy.

Run from the monorepo, where both files exist. On a deployed Kali box the
original is absent and this test is skipped -- the drift can only be introduced
here, so it only needs catching here.
"""

import hashlib
from pathlib import Path

import pytest

VENDORED = Path(__file__).resolve().parents[1] / "attack_runner" / "camouflage.py"
ORIGINAL = (Path(__file__).resolve().parents[2]
            / "src" / "logdet_eval" / "camouflage.py")


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.mark.skipif(not ORIGINAL.exists(),
                    reason="logdet_eval source absent (deployed Kali box)")
def test_vendored_camouflage_matches_original():
    assert _sha(VENDORED) == _sha(ORIGINAL), (
        "attack_runner/attack_runner/camouflage.py has drifted from "
        "src/logdet_eval/camouflage.py. Re-copy it; do not edit one without "
        "the other -- section 2d requires identical transforms."
    )


def test_vendored_camouflage_is_stdlib_only():
    """The property that lets it be a single vendored file."""
    import ast

    roots = set()
    for node in ast.walk(ast.parse(VENDORED.read_text())):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    assert roots <= {"copy", "random", "re", "datetime", "dataclasses"}
