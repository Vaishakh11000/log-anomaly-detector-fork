"""
make_bundle.py
Pack attack_runner into a tarball to carry to the Kali box.

CLAUDE.md §2c: the SSD holding this repo can only be in one machine at a time, so
the Kali adversary box never has the repo checked out. This writes a
self-contained `attack_runner_kali.tgz` -- the standalone, dependency-free
package plus its tests and README -- that unpacks and runs on Kali with nothing
but Python 3's standard library (see attack_runner/KALI_RUNBOOK.md).

    uv run python attack_runner/make_bundle.py            # -> attack_runner_kali.tgz
    uv run python attack_runner/make_bundle.py --out /tmp # choose the directory

Caches are excluded so the tarball is byte-stable across runs.
"""

import argparse
import tarfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parent          # the attack_runner/ project dir
EXCLUDE = {"__pycache__", ".pytest_cache", ".git"}


def _keep(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
    parts = set(Path(info.name).parts)
    return None if parts & EXCLUDE else info


def main() -> int:
    parser = argparse.ArgumentParser(description="Bundle attack_runner for Kali.")
    parser.add_argument("--out", default=str(PROJECT.parent),
                        help="directory to write attack_runner_kali.tgz into")
    args = parser.parse_args()

    out = Path(args.out) / "attack_runner_kali.tgz"
    with tarfile.open(out, "w:gz") as tar:
        # Archive the whole project dir under the name "attack_runner", so it
        # unpacks to a directory whose root holds pyproject.toml and the package.
        tar.add(PROJECT, arcname="attack_runner", filter=_keep)

    print(f"wrote {out} ({out.stat().st_size // 1024} KB)")
    print("copy to Kali, then: tar xzf attack_runner_kali.tgz && cd attack_runner")
    print("                    python3 -m attack_runner.cli --help")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
