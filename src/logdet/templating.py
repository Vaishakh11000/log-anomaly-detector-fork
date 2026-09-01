"""
templating.py
Online log-template mining with Drain3 (Stage 3).

The pipeline has always had a template column, produced by `preprocessing.
template_message()` -- a hand-written regex that masks IPs, ports, PIDs and bare
numbers. That works because the author knew what an sshd auth line looks like.
It does not generalise: point it at a log format nobody wrote a regex for and it
masks the numbers and leaves everything else alone.

Drain3 mines the templates instead of being told them. It builds a parse tree
over the tokens it has seen and assigns each line to a cluster, so
`Failed password for admin from 1.2.3.4 port 22 ssh2` and
`Failed password for root from 5.6.7.8 port 4022 ssh2` land in one cluster with
the varying positions collapsed to `<*>`.

This module only *produces* the column. Nothing in detection reads it yet --
see CLAUDE.md section 4: a change that alters what the detector scores has to be
re-measured under camouflage before it lands, so mining and consuming are
deliberately separate steps.

Two properties of the miner are worth knowing before trusting a template ID:

*Order dependence.* The cluster a line lands in depends on every line seen
before it. Two corpora, or the same corpus in a different order, do not
generally produce the same numbering. IDs are meaningful only relative to the
miner state that produced them, which is why `TemplateMiner.state_summary()`
exists and why the state can be persisted.

*Templates drift, IDs do not.* `add_log_message` returns the cluster's template
*as of that line*, and the template generalises further as more lines arrive.
The first `Failed password` line is recorded with the whole line as its
template; by the second it is `Failed password for <*> from <*> port <*> ssh2`.
So the stable thing to record per line is the **cluster id**, and the template
*text* is resolved afterwards from the miner's final state
(`template_for` / `templates`). Recording the text per line instead would leave
a corpus whose early rows disagree with its late rows about what one cluster is.
"""

from __future__ import annotations

from pathlib import Path

from drain3 import TemplateMiner as _Drain3TemplateMiner
from drain3.masking import MaskingInstruction
from drain3.template_miner_config import TemplateMinerConfig

from . import config


# Masked before the tree ever sees them, rather than left for the similarity
# threshold to discover. Drain collapses a token position to `<*>` only once it
# has seen two different values there, so without these a corpus containing one
# single IP would mine that IP into the template itself -- and the resulting
# cluster numbering would depend on how varied the traffic happened to be.
# Masking the fields we already know are variable makes the mining depend on the
# log's *grammar* instead of on its accidents.
DEFAULT_MASKING = [
    MaskingInstruction(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP"),
    MaskingInstruction(r"(?<=port )\d+", "PORT"),
    MaskingInstruction(r"(?<=\[)\d+(?=\])", "PID"),
    MaskingInstruction(r"\b0x[0-9a-fA-F]+\b", "HEX"),
]


def build_config() -> TemplateMinerConfig:
    """The Drain3 configuration this project mines with.

    Drain3 reads `drain3.ini` from the working directory if one exists, which
    would make the mined templates depend on where the command was run from.
    Building the config in code keeps it in `config.py` with every other tunable
    (CLAUDE.md section 6) and keeps runs reproducible across directories.
    """
    cfg = TemplateMinerConfig()
    cfg.drain_sim_th = config.DRAIN_SIM_TH
    cfg.drain_depth = config.DRAIN_DEPTH
    cfg.drain_max_children = config.DRAIN_MAX_CHILDREN
    cfg.drain_max_clusters = config.DRAIN_MAX_CLUSTERS
    cfg.parametrize_numeric_tokens = config.DRAIN_PARAMETRIZE_NUMERIC
    cfg.masking_instructions = list(DEFAULT_MASKING)
    cfg.profiling_enabled = False
    return cfg


class TemplateMiner:
    """Assigns each log message a cluster id, mining the clusters as it goes.

    Wraps Drain3 rather than exposing it directly, for three reasons: the
    configuration is fixed here instead of being read from a stray `drain3.ini`,
    the return value is narrowed to the one stable thing (the id), and the
    template text is served from current state so a caller cannot accidentally
    record a stale one.
    """

    def __init__(self, config_override: TemplateMinerConfig | None = None):
        self._miner = _Drain3TemplateMiner(config=config_override or build_config())

    def add(self, message: str) -> int | None:
        """File one message into a cluster and return the cluster id.

        Returns None for a message with no content to mine (empty or blank);
        Drain3 raises on those rather than clustering them, and a blank message
        is a parse artefact, not a template.
        """
        if message is None:
            return None
        message = message.strip()
        if not message:
            return None
        result = self._miner.add_log_message(message)
        return result["cluster_id"]

    def match(self, message: str) -> int | None:
        """Return the cluster this message *would* fall into, mining nothing.

        Used when scoring against a frozen template set: a live line that
        matches no known cluster is itself a signal (a template never seen
        during fitting), and letting it silently create a cluster would erase
        that signal.

        Matching is stricter than mining, and the difference bites: a message
        only matches a cluster whose template already carries `<*>` at every
        position where the two differ. A cluster mined from a *single* line has
        no wildcards yet, so it will not match its own variants -- `Failed
        password for admin ...` mined alone does not match `... for root ...`.
        A template set frozen after too little traffic therefore reports far
        more unmatched lines than it should, which would read as novelty rather
        than as an under-trained miner.
        """
        if not message or not message.strip():
            return None
        cluster = self._miner.match(message.strip())
        return cluster.cluster_id if cluster is not None else None

    def template_for(self, cluster_id: int | None) -> str | None:
        """The template text for a cluster, as the miner understands it *now*."""
        if cluster_id is None:
            return None
        cluster = self._miner.drain.id_to_cluster.get(cluster_id)
        return cluster.get_template() if cluster is not None else None

    def templates(self) -> list[dict]:
        """Every mined cluster: id, template text, and how many lines matched it.

        Sorted by size, largest first -- reading a mined template set starts
        with "what does this log mostly say", and the long tail is where the
        rare events are.
        """
        rows = [
            {
                "template_id": cluster.cluster_id,
                "template": cluster.get_template(),
                "size": cluster.size,
            }
            for cluster in self._miner.drain.clusters
        ]
        rows.sort(key=lambda r: (-r["size"], r["template_id"]))
        return rows

    @property
    def cluster_count(self) -> int:
        return len(self._miner.drain.clusters)

    def save(self, path: str | Path) -> None:
        """Persist the mined state so a later run numbers clusters the same way.

        Without this, a stream fitted on Monday and restarted on Tuesday would
        assign different ids to the same templates, and any model keyed on a
        template id would be scoring against a vocabulary that had silently
        been renumbered.

        The state is written in Drain3's own snapshot format (jsonpickle with
        `keys=True`), but written *only when asked*. Handing Drain3 a
        persistence handler instead makes it snapshot itself every time a
        cluster is created or a template widens, which on a first pass over a
        650k-line corpus is thousands of writes nobody asked for.
        """
        import jsonpickle
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(jsonpickle.dumps(self._miner.drain, keys=True))

    def load(self, path: str | Path) -> None:
        """Restore state written by `save`."""
        import jsonpickle
        drain = jsonpickle.loads(Path(path).read_text(), keys=True)
        self._miner.drain.id_to_cluster = drain.id_to_cluster
        self._miner.drain.clusters_counter = drain.clusters_counter
        self._miner.drain.root_node = drain.root_node


def mine_messages(messages, miner: TemplateMiner | None = None) -> tuple[list[int | None], TemplateMiner]:
    """Mine an iterable of messages. Returns (cluster ids, the miner).

    The miner comes back because the ids alone are not interpretable -- the
    template text lives in its state, and resolving it afterwards is what keeps
    every row of a corpus agreeing on what a cluster means.
    """
    miner = miner or TemplateMiner()
    return [miner.add(m) for m in messages], miner
