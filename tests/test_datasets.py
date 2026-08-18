"""
Corpus acquisition.

"We ran on OpenSSH" has to mean one specific 655,147-line file. These tests
guard the pinning, not the download -- the network is not exercised here.
"""

from pathlib import Path

import pytest

from logdet_eval import datasets


def test_every_corpus_is_pinned_by_checksum_and_line_count():
    for name, corpus in datasets.CORPORA.items():
        assert len(corpus.sha256) == 64, f"{name} has no usable checksum"
        assert corpus.expected_lines > 0
        assert corpus.url.startswith("https://zenodo.org/records/")


def test_openssh_is_the_corpus_the_kill_point_expects():
    """CLAUDE.md §3b picks OpenSSH as primary because its anomalies are
    adversarial. If this changes, the kill point is measuring something else."""
    openssh = datasets.CORPORA["openssh"]
    assert openssh.member == "SSH.log"
    assert openssh.expected_lines == 655147


def test_sha256_of_a_known_file(tmp_path):
    target = tmp_path / "x.bin"
    target.write_bytes(b"loghub")
    assert datasets.sha256_of(target) == "9d5c47ebcda3f81f4e341ce3f6d91ba93b769a7c347f43304fd686261f1588f7"


def test_external_dir_is_outside_version_control():
    """73MB of third-party data does not belong in the repo; the fetcher makes
    it reproducible instead."""
    gitignore = (Path(__file__).resolve().parents[1] / ".gitignore").read_text()
    assert "data/external/" in gitignore


@pytest.mark.slow
def test_fetch_is_idempotent_when_the_corpus_is_present():
    """Only runs if the corpus has already been fetched -- CI has no 73MB
    download budget and this must never trigger one."""
    corpus = datasets.CORPORA["openssh"]
    if not corpus.log_path.exists():
        pytest.skip("corpus not fetched")
    assert datasets.fetch("openssh") == corpus.log_path
