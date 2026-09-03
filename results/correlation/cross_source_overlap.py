"""
cross_source_overlap.py
How much cross-service correlation is actually available in the only real
multi-service corpus this project has?

Stage 4 left "multi-source correlation" open on the grounds that the entity
graph is the structure that makes it possible and nothing yet feeds the graph a
second source. Before building that plumbing, this measures whether there is
anything for it to find.

LogHub's Linux.log is one host (`combo`) carrying genuine multi-service auth
traffic -- sshd, ftpd, su, klogind, login -- which is as close to a real
multi-source corpus as anything available here. A cross-service link exists
when two events from *different* services share a user or a source IP and fall
inside the incident window, which is exactly the condition `EntityGraph.edges`
tests.

Run:  uv run python results/correlation/cross_source_overlap.py
"""

import pandas as pd

from logdet.config import INCIDENT_WINDOW_MINUTES, NON_IDENTITY_VALUES
from logdet.preprocessing import LineParser

CORPUS = "data/external/Linux.log"
AUTH_SERVICES = {"sshd", "ftpd", "su", "klogind", "login", "telnetd"}


def load() -> pd.DataFrame:
    with open(CORPUS, errors="replace") as handle:
        rows = LineParser(year=2026).parse_many(handle)
    frame = pd.DataFrame(rows)
    # `sshd(pam_unix)[1234]` and `sshd[1234]` are the same service
    frame["service"] = (frame["process"].astype(str)
                        .str.replace(r"[\(\[].*", "", regex=True)
                        .str.rstrip(":"))
    frame = frame[frame["service"].isin(AUTH_SERVICES)]
    return frame.dropna(subset=["timestamp"]).sort_values("timestamp")


def cross_service_links(frame: pd.DataFrame, column: str):
    """Pairs of events from different services sharing `column` inside the window."""
    window = pd.Timedelta(minutes=INCIDENT_WINDOW_MINUTES)
    values = frame[column].astype(str)
    usable = frame[frame[column].notna() & ~values.str.lower().isin(NON_IDENTITY_VALUES)]

    count = 0
    by_value: dict[str, int] = {}
    for value, group in usable.groupby(column):
        group = group.sort_values("timestamp")
        times = group["timestamp"].tolist()
        services = group["service"].tolist()
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                if times[j] - times[i] > window:
                    break
                if services[i] != services[j]:
                    count += 1
                    by_value[value] = by_value.get(value, 0) + 1
    return count, by_value


def main() -> None:
    frame = load()
    print(f"{CORPUS}: {len(frame)} auth-service events, "
          f"window {INCIDENT_WINDOW_MINUTES} min")
    for service in sorted(AUTH_SERVICES):
        rows = frame[frame["service"] == service]
        if len(rows):
            print(f"  {service:10s} {len(rows):6d} events")

    for column in ("source_ip", "user"):
        count, by_value = cross_service_links(frame, column)
        print(f"\ncross-service links on {column}: {count}")
        for value, n in sorted(by_value.items(), key=lambda kv: -kv[1]):
            print(f"    {value}: {n}")


if __name__ == "__main__":
    main()
