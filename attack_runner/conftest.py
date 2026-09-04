"""Make `attack_runner` importable when pytest runs from this directory with no
install -- the standalone-on-Kali case (no `pip install -e .`, no repo)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
