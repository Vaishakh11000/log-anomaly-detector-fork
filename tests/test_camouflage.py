"""
The camouflage split, pinned.

`camouflage_events` moved out of adversarial.py into the stdlib-only
`logdet_eval.camouflage`, so that CLAUDE.md section 2d's Kali adversary box can
vendor one file instead of checking out a repo it has no room for. That move
must be invisible: the adversarial suite's numbers, the kill point's verdict
and every figure in `results/` were all measured on corpora these functions
produce, so a transform that shifts by one PID or one random draw silently
makes new results incomparable to old ones without failing anything.

So the check is not "the functions still exist" but the corpus itself: SHA-256
over the camouflaged log and its ground-truth CSV, for two seeds across all
nine conditions. The hashes were captured at the commit *before* the split.

If one of these fails, the camouflage changed. That is a detection-relevant
change under CLAUDE.md section 4 -- re-run the adversarial suite over at least
5 seeds and record the delta before touching the expected value. Editing a
hash to make the test green is worse than deleting the test.
"""

import hashlib
import tempfile
from pathlib import Path

import pytest

from logdet_eval.adversarial import REALISTIC_COMBO, STRATEGIES, camouflage_events
from logdet_eval import generate_logs
from logdet_eval.generate_logs import build_dataset, write_outputs

SEEDS = (1, 2)
CONDITIONS = ([("baseline", [])] + [(name, [name]) for name in STRATEGIES]
              + [("realistic-combo", REALISTIC_COMBO)])

# (log sha256, ground-truth sha256), keyed "<condition>:<seed>".
EXPECTED = {
    "baseline:1": ("110eec9545cf168ab243d2d9f5675451d186962b3eb0e25700313471404e5eef",
                  "1b4ac768a85694ec46ddd660979b9c981c1c361f907fcc085c65ec02d41a9ecf"),
    "temporal:1": ("12729dc6902bb5b6cf511a58fed42c0a417eee4f48e8286a5456bbabc8862eae",
                  "29457f532471295ced9abb2fd504c227779c0e5e2b93a4c257e8b73054554fb7"),
    "slow:1": ("71d081df27a644c9f958be05b061f6c1818b900b61a3943046bc75c46887e754",
              "5d075db6e1726f4c2e4ed307ebff66e16bedace1e740f3abc8d3b31606a6332f"),
    "rephrase:1": ("1f78c286d459622184574552be2b129b11ed0f123867d89cc18a5010dd299910",
                  "1b4ac768a85694ec46ddd660979b9c981c1c361f907fcc085c65ec02d41a9ecf"),
    "mimicry:1": ("033fc4a3a275611dee43fbe532546e9121f42bb3914c5c846f64b4a19d2879f6",
                 "1b4ac768a85694ec46ddd660979b9c981c1c361f907fcc085c65ec02d41a9ecf"),
    "noise:1": ("ff452728d6ae517614376e4f7b90adae29ff95ec8e28f143f098ccaafbbccdf3",
               "beceb0f6243e7f1f9543b854e025a58985b3d5217f2d567b0dec93f2045f7222"),
    "volume:1": ("9f7991c6393dde01474b42c64c3e89fbbbb3e2cbc6820334925f1b4925cc2922",
                "09b9a8332f13710da7d5e570f7e4b9e3aaa30060bb55cabda74b9f061ba7cbd0"),
    "ip_rotate:1": ("92c4f8561ba81360aa0ecb6a4820799c9c25ccc05c730207b3762104d1f0d745",
                   "1b4ac768a85694ec46ddd660979b9c981c1c361f907fcc085c65ec02d41a9ecf"),
    "realistic-combo:1": ("5ca77108e1f0875b594584403217d40fd7e9d4ad5759f9d63665fcb633886212",
                         "4c4e03e4893100f3035d60f2b80001726d4951c886fabb1fa336a51194624558"),
    "baseline:2": ("032676c5bade61675f283565187f7fc721ed416218cdf694858a65ec180a3326",
                  "9730a5c73835a05fee247f2b1e10432f9cd845d50fd53cc8a733be8988ef29d1"),
    "temporal:2": ("260a9628a73f91571a195250f7f21974b6a24f0b843c3782c925ac38b1560cad",
                  "c703bc2a48faa363285e06a0936f29280129a551e57731f004ed90ddb2aea6a1"),
    "slow:2": ("9f9ca0de8f333bc566aac1ca506c6da750c5cbcacf337dc0c282628c194a8484",
              "9bfffad57ae9bbe9c9a92e527ede8bf9289c529b007b67b74288aff6c2fd70f6"),
    "rephrase:2": ("d1b27c4789fbbe269bd83a3402740eda729f9d4ac1552122eddb2ac606586b23",
                  "9730a5c73835a05fee247f2b1e10432f9cd845d50fd53cc8a733be8988ef29d1"),
    "mimicry:2": ("0ebeef30c84f8da74ceb035fb900105d3dae7c4a3a59da5c7b5316f4ed932bd3",
                 "9730a5c73835a05fee247f2b1e10432f9cd845d50fd53cc8a733be8988ef29d1"),
    "noise:2": ("f1068facd478ff626063c43a9ba2258ad7ec2c386adbd24cc8e96b8dbb47c030",
               "51adc8336d6eda9c0a032a6586bc9d76018b8a48638b333709075c1b1ee35860"),
    "volume:2": ("f0b18b66eeab556453278bc08e5c3dbd31212f1074a7de3d0206bd4c36532c5d",
                "902ab6ba9447789c2adb47d44b325143625ed0e409284a436ce3c6392b92dde3"),
    "ip_rotate:2": ("dc6a9d16144fede5a9c5a63be0a8c29aaf0ad7201e30707337739218b81669ee",
                   "9730a5c73835a05fee247f2b1e10432f9cd845d50fd53cc8a733be8988ef29d1"),
    "realistic-combo:2": ("a4cf83d1e68a6992da72028e7e73d64820f4d8f49f1cc0b7a4be4c18c9517aa9",
                         "21699de8edd5697f8a8c8b17cfdfe4b0389e15c97f6e6fc481fb024456d3be79"),
}


@pytest.fixture(scope="module")
def corpus_hashes() -> dict[str, tuple[str, str]]:
    """Every corpus the suite builds, in the order `adversarial.main` builds it.

    The order is load-bearing rather than incidental. `generate_logs.next_pid`
    increments a process-global counter that `build_dataset` does not reset, so
    a PID -- and therefore the bytes of the log -- depends on how many events
    have been generated in this interpreter already. That makes the corpus
    reproducible *for a given call sequence*, which is what `main()` fixes: one
    `build_dataset` per seed, then the nine conditions in order. Building each
    condition from its own fresh `build_dataset` would produce a different
    (equally valid, differently numbered) corpus, so the fixture mirrors the
    suite instead of the parametrisation, and resets the counter first so the
    result does not depend on which other tests ran before it.
    """
    # Start from the value a fresh interpreter has, which is what every real
    # `logdet-adversarial` run starts from. Without this the hashes depend on
    # which other tests ran first (see the docstring above), and the suite and
    # the standalone file disagree.
    generate_logs._pid_counter = 1000

    out: dict[str, tuple[str, str]] = {}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for seed in SEEDS:
            base = build_dataset(seed=seed)
            for condition, strategies in CONDITIONS:
                events = camouflage_events(base, strategies, seed) if strategies else base
                log, ground_truth = tmp / "c.log", tmp / "c.csv"
                write_outputs(events, str(log), str(ground_truth))
                out[f"{condition}:{seed}"] = (
                    hashlib.sha256(log.read_bytes()).hexdigest(),
                    hashlib.sha256(ground_truth.read_bytes()).hexdigest())
    return out


@pytest.mark.parametrize("key", list(EXPECTED))
def test_camouflaged_corpus_is_byte_identical(key, corpus_hashes):
    assert corpus_hashes[key] == EXPECTED[key]


def test_camouflage_module_is_stdlib_only():
    """The property that lets Kali vendor this one file.

    Checked over the source rather than by importing, so it fails even for an
    import inside a function that never runs on this box.
    """
    import ast

    src = Path(__file__).resolve().parents[1] / "src" / "logdet_eval" / "camouflage.py"
    roots = set()
    for node in ast.walk(ast.parse(src.read_text())):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    assert roots <= {"copy", "random", "re", "datetime", "dataclasses"}, (
        f"camouflage.py imports {roots}; it must stay stdlib-only so "
        "attack_runner/ can vendor it as a single file."
    )


def test_adversarial_still_exports_the_camouflage_api():
    """Four modules import these from adversarial. The split must not move them."""
    import logdet_eval.adversarial as adv

    for name in ("camouflage_events", "STRATEGIES", "REALISTIC_COMBO",
                 "rephrase_message", "mimic_message", "rotate_ip",
                 "reduce_volume", "spread_timestamps", "make_noise_events"):
        assert hasattr(adv, name), name


def test_synthetic_camouflage_uses_the_corpus_pid_counter():
    """Noise PIDs come from generate_logs' counter, not camouflage's fallback.

    An independent counter renumbers every injected noise line and silently
    changes the corpus -- which is exactly what the hashes above catch, but
    this says why in one assertion.
    """
    from logdet_eval import camouflage
    from logdet_eval.generate_logs import next_pid

    before = camouflage._pid_counter
    events = build_dataset(seed=1)
    camouflage_events(events, ["noise"], seed=1)
    assert camouflage._pid_counter == before, (
        "the synthetic path fell back to camouflage.default_pid"
    )
    assert next_pid.__module__ == "logdet_eval.generate_logs"
