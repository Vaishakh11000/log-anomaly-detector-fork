"""
Paths resolve against the repo root, not the working directory.

v1 used bare relative strings, so any command run from outside the project
root wrote its output somewhere unexpected. pytest in particular runs from
wherever it is invoked.
"""

import os
import subprocess
import sys
from pathlib import Path

from logdet import config

REPO = Path(__file__).resolve().parents[1]


def test_data_paths_are_absolute_and_under_the_repo():
    for value in (config.RAW_DATA_DIR, config.PROCESSED_DATA_DIR,
                  config.DEFAULT_INCIDENTS_PATH, config.RESULTS_DIR):
        path = Path(value)
        assert path.is_absolute(), f"{value} is relative and depends on cwd"
        assert REPO in path.parents or path == REPO


def test_results_never_point_at_the_frozen_v1_baseline():
    """docs/results.v1/ is the historical baseline every change is measured
    against. Nothing may be configured to write into it (CLAUDE.md section 6)."""
    frozen = REPO / "docs" / "results.v1"
    assert frozen not in Path(config.RESULTS_DIR).parents
    assert Path(config.RESULTS_DIR) != frozen


def test_project_root_can_be_overridden_for_scratch_runs(tmp_path):
    """Needed so an eval run can be pointed at a throwaway tree."""
    env = {**os.environ, "LOGDET_PROJECT_ROOT": str(tmp_path)}
    out = subprocess.run(
        [sys.executable, "-c",
         "from logdet.config import RAW_DATA_DIR; print(RAW_DATA_DIR)"],
        capture_output=True, text=True, env=env, check=True,
    )
    assert out.stdout.strip() == str(tmp_path / "data" / "raw")


def test_embedding_settings_are_not_duplicated_in_the_module():
    """config.py is the single source of truth (CLAUDE.md section 6). These two
    values sat hardcoded in embedding.py while config carried its own copy --
    identical by luck, and a silent drift waiting to happen."""
    source = (REPO / "src" / "logdet" / "embedding.py").read_text()
    assert "EMBEDDING_MODEL" in source and "EMBEDDING_BATCH_SIZE" in source
    assert '"all-MiniLM-L6-v2"' not in source
    assert "batch_size=64" not in source
