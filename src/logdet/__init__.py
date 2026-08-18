"""
logdet -- the detection pipeline.

Ingestion -> parsing -> embeddings -> anomaly detection -> incident grouping ->
MITRE mapping -> LLM narrative, plus the interfaces over them.

This package must never import `logdet_eval`. Measuring a system with code the
system depends on is how benchmarks lie (CLAUDE.md section 5); the one-way
dependency is asserted in tests/test_layering.py.
"""

__version__ = "0.2.0.dev0"
