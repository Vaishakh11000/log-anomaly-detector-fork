"""
datasets.py
Fetches the real-world log corpora the benchmark runs against.

LogHub (Zenodo record 8196385) is pinned by record ID and verified by SHA-256,
so "we ran on OpenSSH" means a specific 655,147-line file and not whatever the
URL happened to serve that day. The archives are ~4.8MB and expand to ~76MB,
which is why they are downloaded rather than committed.

Corpus choice is argued in CLAUDE.md section 3b: OpenSSH is primary because its
anomalies are *adversarial* (real internet brute force), which is what MITRE
mapping, narrative, and camouflage all need. HDFS and BGL are labelled but their
anomalies are hardware faults, where none of those three mean anything.
"""

import hashlib
import tarfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from logdet.config import DATA_DIR

EXTERNAL_DIR = DATA_DIR / "external"
ZENODO_RECORD = 8196385


@dataclass(frozen=True)
class Corpus:
    """One downloadable corpus. `member` is the file inside the archive."""

    name: str
    archive: str
    member: str
    sha256: str
    expected_lines: int

    @property
    def url(self) -> str:
        return f"https://zenodo.org/records/{ZENODO_RECORD}/files/{self.archive}"

    @property
    def archive_path(self) -> Path:
        return EXTERNAL_DIR / self.archive

    @property
    def log_path(self) -> Path:
        return EXTERNAL_DIR / self.member


CORPORA = {
    # 655,147 lines from one host (LabSZ), Dec 10 - Jan 07. Almost entirely
    # sshd. Contains real brute force from the open internet -- see
    # corpus_openssh.py for what that means for using it as a background.
    "openssh": Corpus(
        name="openssh",
        archive="SSH.tar.gz",
        member="SSH.log",
        sha256="296610a35773f58b7c295e5407fc5ccdf48beb3c544fc14a6309addf904a2712",
        expected_lines=655147,
    ),
    # Companion corpus: mixed kernel/ftpd/su traffic from a different host.
    # Note only ~76% parses with the current regex -- `su(pam_unix)[123]:`
    # carries parentheses in the process field. Logged under Known Issues.
    "linux": Corpus(
        name="linux",
        archive="Linux.tar.gz",
        member="Linux.log",
        sha256="7e1f820d8d45ae086032e515d9ce8d079a102a9b37dcff5b41a8e60b1f857820",
        expected_lines=25567,
    ),
}


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(name: str, force: bool = False) -> Path:
    """Download, verify and extract one corpus. Returns the log file path.

    Idempotent: an already-extracted corpus is returned untouched unless
    `force`, so this is safe to call at the top of an evaluation run.
    """
    corpus = CORPORA[name]
    EXTERNAL_DIR.mkdir(parents=True, exist_ok=True)

    if corpus.log_path.exists() and not force:
        return corpus.log_path

    if not corpus.archive_path.exists() or force:
        print(f"Downloading {corpus.archive} from Zenodo record {ZENODO_RECORD}...")
        urllib.request.urlretrieve(corpus.url, corpus.archive_path)

    actual = sha256_of(corpus.archive_path)
    if actual != corpus.sha256:
        raise RuntimeError(
            f"{corpus.archive} failed verification.\n"
            f"  expected {corpus.sha256}\n  got      {actual}\n"
            "Refusing to benchmark against an unverified corpus."
        )

    with tarfile.open(corpus.archive_path) as archive:
        archive.extractall(EXTERNAL_DIR, filter="data")

    return corpus.log_path


def cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Fetch the LogHub benchmark corpora.")
    parser.add_argument("--corpus", choices=sorted(CORPORA) + ["all"], default="all")
    parser.add_argument("--force", action="store_true", help="re-download and re-verify")
    args = parser.parse_args()

    names = sorted(CORPORA) if args.corpus == "all" else [args.corpus]
    for name in names:
        path = fetch(name, force=args.force)
        lines = sum(1 for _ in open(path, errors="ignore"))
        expected = CORPORA[name].expected_lines
        flag = "ok" if lines == expected else f"WARNING: expected {expected}"
        print(f"{name}: {lines} lines -> {path}  [{flag}]")


if __name__ == "__main__":
    cli()
