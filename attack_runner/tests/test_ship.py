"""Shipper: retry, byte-offset resume, disk buffer, idempotence.

No network -- a fake opener records calls and can be told to fail, which is how
the retry and resume paths get exercised (CLAUDE.md section 2c reliability
requirements).
"""

from attack_runner.ship import Shipper


class FakeOpener:
    def __init__(self, fail_times=0, status=200):
        self.fail_times = fail_times
        self.status = status
        self.bodies = []

    def __call__(self, url, body):
        self.bodies.append(body)
        if self.fail_times > 0:
            self.fail_times -= 1
            raise OSError("simulated link down")
        return self.status


def test_ship_success_commits_offset(tmp_path):
    opener = FakeOpener()
    s = Shipper("http://x/ingest", tmp_path, opener=opener, backoff=0)
    r = s.ship(["line one", "line two"])
    assert r.ok and r.sent == 2 and r.committed_offset == 2
    assert len(opener.bodies) == 1


def test_flush_is_idempotent_after_success(tmp_path):
    opener = FakeOpener()
    s = Shipper("http://x/ingest", tmp_path, opener=opener, backoff=0)
    s.ship(["a"])
    r = s.flush()   # nothing pending
    assert r.sent == 0 and r.ok


def test_retry_then_succeed(tmp_path):
    opener = FakeOpener(fail_times=2)
    s = Shipper("http://x/ingest", tmp_path, opener=opener, backoff=0, max_retries=5)
    r = s.ship(["a", "b"])
    assert r.ok and r.sent == 2
    assert len(opener.bodies) == 3   # two failures + one success


def test_exhausted_retries_leaves_offset_uncommitted(tmp_path):
    opener = FakeOpener(fail_times=99)
    s = Shipper("http://x/ingest", tmp_path, opener=opener, backoff=0, max_retries=3)
    r = s.ship(["a", "b"])
    assert not r.ok and r.committed_offset == 0
    assert s.last_error is not None


def test_resume_from_spool_after_crash(tmp_path):
    """A second Shipper on the same spool resends exactly what the first could
    not commit -- no duplicates, no skips."""
    down = FakeOpener(fail_times=99)
    s1 = Shipper("http://x/ingest", tmp_path, opener=down, backoff=0, max_retries=1)
    s1.ship(["a", "b", "c"])              # all spooled, none committed

    up = FakeOpener()
    s2 = Shipper("http://x/ingest", tmp_path, opener=up, backoff=0)
    r = s2.flush()                        # resumes from offset 0
    assert r.ok and r.sent == 3 and r.committed_offset == 3

    r2 = s2.flush()                       # nothing left
    assert r2.sent == 0


def test_status_reports_pending(tmp_path):
    down = FakeOpener(fail_times=99)
    s = Shipper("http://x/ingest", tmp_path, opener=down, backoff=0, max_retries=1)
    s.ship(["a", "b"])
    st = s.status()
    assert st["spooled"] == 2 and st["committed"] == 0 and st["pending"] == 2
    assert st["last_error"]
