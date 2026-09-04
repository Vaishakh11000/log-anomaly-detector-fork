"""
linkcheck.py
Verify the Kali box can reach the analyzer, one layer at a time.

CLAUDE.md section 2c is emphatic that the link is chosen for *reliability*, not
throughput, and that its health must be answerable by looking rather than
inferred from an absence of alerts. This is the "by looking" tool: it walks the
stack from wire to application and prints one line per layer, so when something
is wrong you can see *which* layer, not just that "it doesn't work".

Transport-agnostic on purpose. Section 2c leaves the physical link open --
direct Cat6 is the default, Thunderbolt/USB4 host-to-host is faster if both
ends have it, a USB-C ethernet dongle also works; a plain USB-C cable is *not*
a network and is excluded by design. This checker does not care which of those
is underneath: it finds the local interface by its 10.10.10.x address rather
than by name (enp3s0 / thunderbolt0 / enxXXXX all differ), so the same command
passes on every valid transport and fails only when there is genuinely no
L2/L3/L7 path.

The four layers:
  L2  a local interface holds an address on the link subnet
  L3  the analyzer's IP answers ping
  L7  GET /health returns 200
  lag GET /stream/status -- seconds_since_last_batch, so a connected-but-stalled
      analyzer is distinguishable from a healthy one

stdlib only (urllib/subprocess): runs on a bare Kali box. Exit code 0 only when
every enabled layer passes, so it drops straight into a shell `&&` or CI.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import subprocess
import sys
import urllib.error
import urllib.request

OK = "OK  "
FAIL = "FAIL"
SKIP = "SKIP"


def _line(layer: str, verdict: str, detail: str) -> str:
    return f"[{verdict}] {layer:<4} {detail}"


def local_interface_on_subnet(subnet: str, runner=subprocess.run) -> tuple[bool, str]:
    """L2: is any local interface addressed on `subnet`?

    Found by address, not interface name, so the check is identical whether the
    link is Cat6, Thunderbolt or a dongle. Parses `ip -o -4 addr`, which is on
    every Kali box; no netifaces dependency.
    """
    net = ipaddress.ip_network(subnet, strict=False)
    try:
        proc = runner(["ip", "-o", "-4", "addr", "show"],
                      capture_output=True, text=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        return False, f"could not read interfaces: {exc}"
    for row in proc.stdout.splitlines():
        parts = row.split()
        # "<idx>: <iface> inet <ip>/<prefix> ..."
        if len(parts) >= 4 and parts[2] == "inet":
            addr = parts[3].split("/")[0]
            iface = parts[1]
            try:
                if ipaddress.ip_address(addr) in net:
                    return True, f"{iface} has {addr} on {subnet}"
            except ValueError:
                continue
    return False, f"no interface addressed on {subnet}"


def ping(host: str, runner=subprocess.run) -> tuple[bool, str]:
    """L3: does the peer answer ICMP? One packet, 2s deadline."""
    try:
        proc = runner(["ping", "-c", "1", "-W", "2", host],
                      capture_output=True, text=True)
    except FileNotFoundError:
        return False, "ping not found"
    if proc.returncode == 0:
        return True, f"{host} answered ping"
    return False, f"{host} did not answer ping"


def http_health(base_url: str, timeout: float = 5.0, opener=None) -> tuple[bool, str]:
    """L7: GET /health -> 200."""
    opener = opener or _urlopen
    url = base_url.rstrip("/") + "/health"
    try:
        status, _ = opener(url, timeout)
    except (urllib.error.URLError, OSError, socket.timeout) as exc:
        return False, f"{url} unreachable: {exc}"
    if status == 200:
        return True, f"{url} -> 200"
    return False, f"{url} -> {status}"


def stream_lag(base_url: str, timeout: float = 5.0, opener=None) -> tuple[bool, str]:
    """Application layer: /stream/status, seconds_since_last_batch.

    A connected analyzer that has stopped scoring is *worse* than a down one,
    because it looks alive. This surfaces that. Not having a stream running yet
    is not a failure -- the field is null before the first batch -- so this
    reports SKIP-shaped info rather than FAIL in that case.
    """
    opener = opener or _urlopen
    url = base_url.rstrip("/") + "/stream/status"
    try:
        status, body = opener(url, timeout)
    except (urllib.error.URLError, OSError, socket.timeout) as exc:
        return False, f"{url} unreachable: {exc}"
    if status != 200:
        return False, f"{url} -> {status}"
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return False, f"{url} returned non-JSON"
    lag = data.get("seconds_since_last_batch")
    if not data.get("running"):
        return True, "no stream running (nothing to lag)"
    if lag is None:
        return True, "stream up, no batch scored yet"
    return True, f"last batch {lag:.1f}s ago"


def _urlopen(url: str, timeout: float) -> tuple[int, str]:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode("utf-8", "replace")


def run_checks(subnet: str, peer: str, base_url: str,
               check_l2: bool = True, runner=subprocess.run,
               opener=None) -> tuple[bool, list[str]]:
    """Run every layer, return (all_ok, printable lines).

    `check_l2` is off for a loopback self-test, where there is no link subnet.
    """
    lines: list[str] = []
    ok = True

    if check_l2:
        passed, detail = local_interface_on_subnet(subnet, runner=runner)
        ok &= passed
        lines.append(_line("L2", OK if passed else FAIL, detail))
    else:
        lines.append(_line("L2", SKIP, "loopback mode, no link subnet"))

    passed, detail = ping(peer, runner=runner)
    ok &= passed
    lines.append(_line("L3", OK if passed else FAIL, detail))

    passed, detail = http_health(base_url, opener=opener)
    ok &= passed
    lines.append(_line("L7", OK if passed else FAIL, detail))

    # lag never fails the overall verdict -- it is diagnostic, not a gate --
    # but its tag still reflects whether /stream/status was reachable, so an
    # unreachable status line does not read as OK.
    lag_ok, detail = stream_lag(base_url, opener=opener)
    lines.append(_line("lag", OK if lag_ok else FAIL, detail))

    lines.append("LINK OK" if ok else "LINK DOWN")
    return ok, lines


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Verify the Kali->analyzer link, layer by layer.")
    p.add_argument("--peer", default="10.10.10.2",
                   help="analyzer IP on the link (default the section 2c address)")
    p.add_argument("--subnet", default="10.10.10.0/24",
                   help="link subnet the local interface should be addressed on")
    p.add_argument("--port", type=int, default=8000, help="analyzer API port")
    p.add_argument("--loopback", action="store_true",
                   help="self-test against 127.0.0.1, skipping the L2 subnet check")
    args = p.parse_args(argv)

    peer = "127.0.0.1" if args.loopback else args.peer
    base_url = f"http://{peer}:{args.port}"
    ok, lines = run_checks(args.subnet, peer, base_url, check_l2=not args.loopback)
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
