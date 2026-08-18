"""
The architectural rule from CLAUDE.md section 5, made enforceable.

  "The evaluation track must never be imported by the pipeline, and baseline
   rule implementations must never leak into detection."

Measuring a system with code that system depends on is how benchmarks lie.
This is checked statically (AST over the source), not by importing, so a
violation fails CI even if the offending path never executes.
"""

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
PIPELINE_MODULES = sorted((SRC / "logdet").glob("*.py"))


def imported_modules(path: Path) -> set[str]:
    """Every dotted module name a module imports."""
    tree = ast.parse(path.read_text())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
            names.update(f"{node.module}.{a.name}" for a in node.names)
    return names


def imported_roots(path: Path) -> set[str]:
    """Top-level package names imported by a module."""
    tree = ast.parse(path.read_text())
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


@pytest.mark.parametrize("module", PIPELINE_MODULES, ids=lambda p: p.name)
def test_pipeline_never_imports_the_evaluation_track(module: Path):
    assert "logdet_eval" not in imported_roots(module), (
        f"{module.name} imports the evaluation track. The dependency runs one "
        "way only: logdet_eval may import logdet, never the reverse."
    )


@pytest.mark.parametrize("module", PIPELINE_MODULES, ids=lambda p: p.name)
def test_no_baseline_rules_in_the_pipeline(module: Path):
    """The rule baseline is what the detector is measured against. If it ever
    becomes part of the detector, the comparison stops meaning anything.

    Checks imports rather than the bare string: a comment explaining why the
    baseline is kept out is welcome, an import of it is not."""
    imports = {name for name in imported_modules(module)}
    assert not any("baseline_rules" in name for name in imports), (
        f"{module.name} imports the rule baseline -- see Anti-Goals in CLAUDE.md."
    )


def test_no_copy_of_the_baseline_lives_inside_the_pipeline():
    """The other way to break the rule: paste the rules in rather than import."""
    assert not (SRC / "logdet" / "baseline_rules.py").exists()


def test_evaluation_track_is_allowed_to_import_the_pipeline():
    """The converse direction is required, not merely tolerated -- the harness
    has to score the real detector, not a copy of it."""
    adversarial = SRC / "logdet_eval" / "adversarial.py"
    assert "logdet" in imported_roots(adversarial)
