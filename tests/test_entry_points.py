"""
The console scripts declared in pyproject.toml actually resolve.

A broken entry point is invisible until someone runs the command, which is
typically in front of an examiner.
"""

import importlib
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["scripts"]


@pytest.mark.parametrize("name, target", sorted(SCRIPTS.items()))
def test_entry_point_target_exists(name: str, target: str):
    module_name, _, attr = target.partition(":")
    module = importlib.import_module(module_name)
    assert callable(getattr(module, attr)), f"{target} is not callable"


@pytest.mark.parametrize("name", sorted(SCRIPTS))
def test_entry_point_help_runs(name: str):
    """--help exercises argparse setup, which is where the cwd-relative
    defaults used to hide."""
    result = subprocess.run([name, "--help"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout


def test_modules_are_importable_without_a_running_ollama():
    """Import must never reach out to a service -- CI has no Ollama."""
    for module in ("logdet.pipeline", "logdet.llm_narrative", "logdet.mitre_mapping",
                   "logdet_eval.evaluate", "logdet_eval.adversarial"):
        importlib.import_module(module)
