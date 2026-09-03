"""
Tests for the entity graph (Stage 4).

The load-bearing one is `test_matches_pairwise_grouper_on_random_frames`: the
graph replaced a pairwise backward scan that produced every incident count in
`results/`, so the claim that the partition is unchanged has to be asserted
against the old algorithm rather than argued. The old implementation is kept
here as a reference oracle for exactly that reason -- if a future change to the
graph alters grouping, this fails, and CLAUDE.md section 4 applies.
"""

import pandas as pd
import pytest

from logdet.entity_graph import Entity, EntityGraph, normalise_identity
from logdet.sequence_grouping import group_anomalies


# --- the pre-Stage-4 grouper, kept as an oracle -----------------------------

class _OldUnionFind:
    def __init__(self, size):
        self.parent = list(range(size))

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, x, y):
        rx, ry = self.find(x), self.find(y)
        if rx != ry:
            self.parent[max(rx, ry)] = min(rx, ry)


def _old_linked(a, b, group_by_source_ip):
    ua, ub = normalise_identity(a.get("user")), normalise_identity(b.get("user"))
    if ua is not None and ua == ub:
        return True
    if group_by_source_ip:
        ia, ib = normalise_identity(a.get("source_ip")), normalise_identity(b.get("source_ip"))
        if ia is not None and ia == ib:
            return True
    return False


def old_group_anomalies(df, window_minutes=30, group_by_source_ip=True,
                        time_col="timestamp"):
    """The all-pairs backward scan this module replaced, verbatim in behaviour."""
    anomalies = df[df["is_anomaly"] == True].copy()
    anomalies = anomalies.dropna(subset=[time_col]).sort_values(time_col).reset_index(drop=True)
    if anomalies.empty:
        return []

    window = pd.Timedelta(minutes=window_minutes)
    groups = _OldUnionFind(len(anomalies))
    for i in range(len(anomalies)):
        row_i = anomalies.iloc[i]
        for j in range(i - 1, -1, -1):
            row_j = anomalies.iloc[j]
            if row_i[time_col] - row_j[time_col] > window:
                break
            if _old_linked(row_i, row_j, group_by_source_ip):
                groups.union(i, j)

    incidents = {}
    for i in range(len(anomalies)):
        incidents.setdefault(groups.find(i), []).append(i)
    return [anomalies.iloc[idx].reset_index(drop=True) for idx in incidents.values()]


def _shape(incidents, column="message"):
    """Comparable form: the ordered list of each incident's ordered messages."""
    return [list(inc[column]) for inc in incidents]


# --- equivalence ------------------------------------------------------------

def _random_frame(rng, rows):
    users = ["alice", "bob", "root", "unknown", None]
    ips = ["10.0.0.5", "10.0.0.9", "203.0.113.7", "unknown", None]
    start = pd.Timestamp("2026-07-18 09:00:00")
    return pd.DataFrame({
        "user": [users[rng.integers(len(users))] for _ in range(rows)],
        "source_ip": [ips[rng.integers(len(ips))] for _ in range(rows)],
        "timestamp": [start + pd.Timedelta(minutes=int(rng.integers(0, 400)))
                      for _ in range(rows)],
        "is_anomaly": [True] * rows,
        "message": [f"line {i}" for i in range(rows)],
    })


@pytest.mark.parametrize("seed", range(12))
@pytest.mark.parametrize("group_by_source_ip", [True, False])
def test_matches_pairwise_grouper_on_random_frames(seed, group_by_source_ip):
    """The graph partition is the old partition, not an approximation of it."""
    import numpy as np
    rng = np.random.default_rng(seed)
    frame = _random_frame(rng, rows=40)

    new = group_anomalies(frame, group_by_source_ip=group_by_source_ip)
    old = old_group_anomalies(frame, group_by_source_ip=group_by_source_ip)

    assert _shape(new) == _shape(old)


def test_matches_pairwise_grouper_on_a_transitive_chain():
    """A -> B -> C where A and C are 50 minutes apart is still one incident:
    the property the consecutive-pairs argument turns on."""
    frame = pd.DataFrame({
        "user": ["alice"] * 3,
        "source_ip": ["10.0.0.5"] * 3,
        "timestamp": pd.to_datetime(["2026-07-18 10:00:00",
                                     "2026-07-18 10:25:00",
                                     "2026-07-18 10:50:00"]),
        "is_anomaly": [True] * 3,
        "message": ["a", "b", "c"],
    })
    assert _shape(group_anomalies(frame)) == _shape(old_group_anomalies(frame))
    assert len(group_anomalies(frame)) == 1


def test_empty_and_unflagged_frames_group_to_nothing():
    frame = pd.DataFrame({"user": ["alice"], "source_ip": ["10.0.0.5"],
                          "timestamp": pd.to_datetime(["2026-07-18 10:00:00"]),
                          "is_anomaly": [False], "message": ["a"]})
    assert group_anomalies(frame) == []
    assert group_anomalies(frame.iloc[0:0]) == []


# --- graph structure --------------------------------------------------------

@pytest.fixture
def frame():
    return pd.DataFrame({
        "user": ["alice", "alice", "bob", "unknown"],
        "source_ip": ["10.0.0.5", "203.0.113.7", "192.168.4.4", "10.0.0.5"],
        "host": ["srv1"] * 4,
        "process": ["sshd"] * 4,
        "timestamp": pd.to_datetime(["2026-07-18 10:00:00", "2026-07-18 10:10:00",
                                     "2026-07-18 10:20:00", "2026-07-18 10:25:00"]),
        "message": ["a", "b", "c", "d"],
    })


def test_entities_come_from_every_configured_column(frame):
    graph = EntityGraph.build(frame)
    kinds = {entity.kind for entity in graph.entities()}
    assert kinds == {"user", "ip", "host", "process"}
    assert Entity("host", "srv1") in graph.entities("host")


def test_placeholder_identities_are_not_nodes(frame):
    """"unknown" is the parser reporting no user, not a user called unknown."""
    graph = EntityGraph.build(frame)
    assert Entity("user", "unknown") not in graph.entities()
    assert graph.entities_of[3] == frozenset({Entity("ip", "10.0.0.5"),
                                              Entity("host", "srv1"),
                                              Entity("process", "sshd")})


def test_host_and_process_are_nodes_but_not_grouping_links(frame):
    """Every line shares the host, so a host edge would merge the whole log."""
    graph = EntityGraph.build(frame)
    assert len(graph.components()) > 1
    assert len(graph.components(kinds=("user", "ip", "host"))) == 1


def test_edges_outside_the_window_are_not_edges():
    frame = pd.DataFrame({
        "user": ["alice", "alice"],
        "source_ip": ["10.0.0.5", "10.0.0.5"],
        "timestamp": pd.to_datetime(["2026-07-18 10:00:00", "2026-07-18 12:00:00"]),
        "message": ["a", "b"],
    })
    graph = EntityGraph.build(frame, window_minutes=30)
    assert graph.edges() == []
    assert graph.components() == [[0], [1]]


def test_neighbours_sees_unflagged_traffic(frame):
    """The query union-find could not answer: what else touches this IP?

    Positions 0 and 3 share 10.0.0.5 within the window, and neither is flagged
    -- the graph is built over the whole frame, not over the alerts.
    """
    graph = EntityGraph.build(frame)
    assert graph.neighbours(0, kinds=("ip",)) == [3]
    assert graph.degree(0, "ip") == 1
    assert graph.degree(1, "ip") == 0


def test_preceding_returns_the_event_compared_against(frame):
    """What an impossible-travel hit was judged against: alice's prior login."""
    graph = EntityGraph.build(frame, window_minutes=60)
    assert graph.preceding(1, Entity("user", "alice")) == 0
    assert graph.preceding(0, Entity("user", "alice")) is None


def test_preceding_respects_the_window(frame):
    graph = EntityGraph.build(frame, window_minutes=5)
    assert graph.preceding(1, Entity("user", "alice")) is None


def test_normalise_identity_rejects_placeholders_and_blanks():
    assert normalise_identity("alice") == "alice"
    assert normalise_identity("  alice  ") == "alice"
    assert normalise_identity("UNKNOWN") is None
    assert normalise_identity("") is None
    assert normalise_identity(None) is None
    assert normalise_identity(float("nan")) is None
