"""
entity_graph.py
The entities a log mentions (users, source IPs, hosts, processes), the events
that mention them, and which events are therefore related.

This replaces the pairwise scan `sequence_grouping` used to do. Union-find over
"does row i link to row j" answers one question -- are these two rows in the
same incident -- and throws the structure away. Keeping the graph instead makes
three things askable that were not askable before:

  - **Which other events touch this event's entities?** Union-find only ever
    saw the *flagged* rows, so "this alert is alone" could not distinguish an
    unknown IP appearing once from a busy known host that also logged one odd
    line. Suppression's loneness guard is the safety property doing the work
    (see suppression.py), and this is what a better version of it needs.
  - **What was this event compared against?** The impossible-travel check
    compares a login with that user's previous login; the previous one is
    benign, so it was never carried into the incident and the report shows the
    conclusion without the evidence (Known Issues).
  - **Host and process as first-class nodes**, available for context without
    being allowed to join incidents.

Grouping links on users and source IPs only
-------------------------------------------

`components()` takes the entity kinds it is allowed to traverse, and the
default is the pair the shipped grouper already used. Host and process are
recorded as nodes but are **not** grouping links, and that is not caution: the
LogHub OpenSSH corpus is a single host (`LabSZ`), so a host edge joins all
655,147 lines into one component, and `sshd` does the same for process. An
entity that every event shares carries no information about which events belong
together.

Equivalence with the old grouper
--------------------------------

Chaining each entity's events consecutively is not an approximation of the old
all-pairs scan, it is the same partition. If two events on one entity are
within the window, every consecutive gap between them is also within the
window, so the chain already connects them; and connectivity is transitive
either way. It is also O(events) per entity instead of O(events^2) overall.
`tests/test_entity_graph.py` asserts the two agree on the synthetic corpus and
on randomised frames, and `group_anomalies` is now implemented on top of this
module rather than beside it.
"""

from __future__ import annotations

from typing import Iterable, NamedTuple

import pandas as pd

from logdet.config import (
    INCIDENT_WINDOW_MINUTES,
    NON_IDENTITY_VALUES,
)

# Entity kind -> the parsed column it is read from. Kinds not present in a
# frame are simply absent from the graph rather than an error, because the
# streaming path and the evaluation corpora do not all carry every column.
ENTITY_COLUMNS: dict[str, str] = {
    "user": "user",
    "ip": "source_ip",
    "host": "host",
    "process": "process",
}

# What incidents are allowed to be built from. See the module docstring for
# why host and process are excluded.
GROUPING_KINDS: tuple[str, ...] = ("user", "ip")


class Entity(NamedTuple):
    """One node of the graph: a kind and its value, e.g. ("ip", "203.0.113.7")."""
    kind: str
    value: str

    def __str__(self) -> str:
        return f"{self.kind}:{self.value}"


def normalise_identity(value) -> str | None:
    """A joinable identity, or None when the cell is not one.

    Placeholders like "unknown" are the parser saying it found no user, not a
    user named "unknown". Joining on one would merge unrelated systemd noise
    into a single fake incident, which is why this is shared by the graph, the
    grouper and the incident summary rather than reimplemented in each.
    """
    if value is None or (not isinstance(value, str) and pd.isna(value)):
        return None
    text = str(value).strip()
    if not text or text.lower() in NON_IDENTITY_VALUES:
        return None
    return text


class _Components:
    """Union-find over event positions, used only to close the graph's edges
    into connected components. Membership is transitive: A-B and B-C put A and
    C in one incident even where they share nothing directly."""

    def __init__(self, size: int):
        self.parent = list(range(size))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]   # path compression
            x = self.parent[x]
        return x

    def union(self, x: int, y: int) -> None:
        root_x, root_y = self.find(x), self.find(y)
        if root_x != root_y:
            # keep the lower position as root so incidents stay in chronological order
            self.parent[max(root_x, root_y)] = min(root_x, root_y)


class EntityGraph:
    """Events and the entities they mention, with time-bounded adjacency.

    Positions are into the frame the graph was built from, in the order that
    frame was given -- callers sort before building and read results back by
    position, so nothing here re-orders anything.
    """

    def __init__(self, frame: pd.DataFrame, window: pd.Timedelta,
                 time_col: str = "timestamp"):
        self.frame = frame
        self.window = window
        self.time_col = time_col
        self.entities_of: list[frozenset[Entity]] = []
        self.events_of: dict[Entity, list[int]] = {}

    # --- construction ------------------------------------------------------

    @classmethod
    def build(cls, frame: pd.DataFrame,
              window_minutes: int = INCIDENT_WINDOW_MINUTES,
              kinds: Iterable[str] = tuple(ENTITY_COLUMNS),
              time_col: str = "timestamp") -> "EntityGraph":
        """Index a frame of events. Rows keep their positions.

        Build over *all* rows when the question is about context ("what else
        touches this IP?"), and over the flagged rows alone when the question
        is grouping -- the shipped grouper does the latter, which is why an
        alert has never been able to see the benign traffic around it.
        """
        graph = cls(frame, pd.Timedelta(minutes=window_minutes), time_col)
        columns = {kind: ENTITY_COLUMNS[kind] for kind in kinds
                   if ENTITY_COLUMNS.get(kind) in frame.columns}

        for position in range(len(frame)):
            row = frame.iloc[position]
            entities = set()
            for kind, column in columns.items():
                value = normalise_identity(row[column])
                if value is not None:
                    entities.add(Entity(kind, value))
            graph.entities_of.append(frozenset(entities))
            for entity in entities:
                graph.events_of.setdefault(entity, []).append(position)

        return graph

    # --- structure ---------------------------------------------------------

    def entities(self, kind: str | None = None) -> list[Entity]:
        """Every entity node, optionally of one kind, in a stable order."""
        return sorted(e for e in self.events_of if kind is None or e.kind == kind)

    def _time(self, position: int):
        return self.frame.iloc[position][self.time_col]

    def edges(self, kinds: Iterable[str] = GROUPING_KINDS
              ) -> list[tuple[int, int, Entity]]:
        """Time-bounded adjacency: consecutive events on one entity, when the
        gap between them is inside the window. See the docstring for why
        consecutive pairs give the same components as all pairs."""
        found = []
        for entity, positions in self.events_of.items():
            if entity.kind not in set(kinds):
                continue
            for earlier, later in zip(positions, positions[1:]):
                if abs(self._time(later) - self._time(earlier)) <= self.window:
                    found.append((earlier, later, entity))
        return found

    def components(self, kinds: Iterable[str] = GROUPING_KINDS) -> list[list[int]]:
        """Connected subgraphs as lists of positions.

        Ordered by their lowest member and each member ascending, which is the
        order the pairwise grouper produced and what keeps incident ids stable
        across this change.
        """
        if len(self.frame) == 0:
            return []
        components = _Components(len(self.frame))
        for earlier, later, _ in self.edges(kinds):
            components.union(earlier, later)

        grouped: dict[int, list[int]] = {}
        for position in range(len(self.frame)):
            grouped.setdefault(components.find(position), []).append(position)
        return [grouped[root] for root in sorted(grouped)]

    # --- neighbourhood queries --------------------------------------------

    def neighbours(self, position: int, kinds: Iterable[str] = GROUPING_KINDS,
                   window: pd.Timedelta | None = None) -> list[int]:
        """Other events sharing one of this event's entities, inside the window.

        This is the query union-find could not answer, because it only ever
        held the flagged rows. Built over a full frame it says how much traffic
        an alert's user and IP account for -- corroboration measured against
        everything that happened, not only against other alerts.
        """
        window = self.window if window is None else window
        when = self._time(position)
        found = set()
        wanted = set(kinds)
        for entity in self.entities_of[position]:
            if entity.kind not in wanted:
                continue
            for other in self.events_of[entity]:
                if other != position and abs(self._time(other) - when) <= window:
                    found.add(other)
        return sorted(found)

    def preceding(self, position: int, entity: Entity,
                  window: pd.Timedelta | None = None) -> int | None:
        """The event before this one on `entity`, or None if there is none in
        the window. This is what an impossible-travel hit was compared against."""
        window = self.window if window is None else window
        when = self._time(position)
        best = None
        for other in self.events_of.get(entity, []):
            other_time = self._time(other)
            if other_time > when or other == position:
                continue
            if when - other_time > window:
                continue
            if best is None or other_time >= self._time(best):
                best = other
        return best

    def degree(self, position: int, kind: str,
               window: pd.Timedelta | None = None) -> int:
        """How many other events share this event's entity of one kind."""
        return len(self.neighbours(position, kinds=(kind,), window=window))


if __name__ == "__main__":
    frame = pd.DataFrame({
        "user": ["alice", "alice", "bob", "root", "test", "guest"],
        "source_ip": ["10.0.0.5", "10.0.0.5", "10.0.0.9",
                      "203.0.113.7", "203.0.113.7", "203.0.113.7"],
        "host": ["srv1"] * 6,
        "process": ["sshd"] * 6,
        "timestamp": pd.to_datetime([
            "2026-07-18 10:00:00", "2026-07-18 10:05:00", "2026-07-18 10:00:00",
            "2026-07-18 14:00:00", "2026-07-18 14:01:00", "2026-07-18 14:02:00",
        ]),
    })
    graph = EntityGraph.build(frame)
    print(f"{len(graph.entities())} entity nodes, {len(graph.edges())} edges")
    print("components (user+ip):", graph.components())
    print("components (host too):", graph.components(kinds=("user", "ip", "host")))
    print("^ the host edge merges alice with an unrelated bob, which is why")
    print("  host is recorded as a node but is not a grouping link")
