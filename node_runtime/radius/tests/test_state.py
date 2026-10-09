from __future__ import annotations

import glob
import os
import sqlite3
import stat
import unittest

import rtest
from rtest import BASE, account, ask, plist

import state


def reopen(case, eng, clock=None):
    eng.flush()
    eng.store.close()
    return rtest.make_engine(case, clock=clock or eng.clock, path=eng._test_dir, with_facts=False, seed=99)


class Persistence(unittest.TestCase):
    def setUp(self):
        self.clock = rtest.FakeClock()
        self.eng = rtest.make_engine(self, clock=self.clock)
        self.lists = [
            plist(10, "statica", 1, mode="static"),
            plist(11, "stickyy", 1, mode="sticky", ttlSec=3600),
            plist(12, "rotaaaa", 2),
        ]
        self.eng.dispatch(
            {"op": "snapshot", "seq": 42, "accounts": [account(1), account(2)], "lists": self.lists, "static": []}
        )

    def test_static_and_sticky_survive_a_restart(self):
        e = self.eng
        s = ask(e, "netrun-statica", port=BASE + 4)
        k = ask(e, "netrun-stickyy", port=BASE + 5)
        ses = ask(e, "netrun-stickyy-session-abc-ttl-2h")
        ask(e, "netrun-rotaaaa", password="bad")
        e.dispatch({"op": "local_block", "accountId": 2, "blocked": True})
        e.dispatch({"op": "excluded", "nets": [7, 8, 9], "complete": True, "scanId": "s1"})
        reserved = e.dispatch({"op": "reserve_nets", "count": 3, "ref": "job-9"})["nets"]
        released = e.dispatch({"op": "release_nets", "nets": [reserved[0]], "ref": "dep-9"})
        e.dispatch({"op": "heartbeat", "at": self.clock(), "near": {"1": 5 << 30}})
        epoch = e.epoch
        self.clock.advance(30)
        e2 = reopen(self, e)
        self.assertEqual((e2.epoch, e2.seq), (epoch, 42))
        self.assertFalse(e2.db_recovered)
        self.assertTrue(e2.dispatch({"op": "status"})["ready"])  # facts persisted
        self.assertEqual(ask(e2, "netrun-statica", port=BASE + 4).addr, s.addr)
        self.assertEqual(ask(e2, "netrun-stickyy", port=BASE + 5).addr, k.addr)
        self.assertEqual(ask(e2, "netrun-stickyy-session-abc-ttl-2h").addr, ses.addr)
        self.assertEqual(e2.dispatch({"op": "rejects"})["lists"]["12"]["reason"], "bad_login")
        self.assertTrue(e2.accounts[2].local_blocked)
        self.assertEqual(e2.dispatch({"op": "reserve_nets", "count": 3, "ref": "job-9"})["nets"], reserved)
        self.assertEqual(e2.dispatch({"op": "release_nets", "nets": [reserved[0]], "ref": "dep-9"}), released)
        a = e2.alloc
        for n in (7, 8, 9):
            self.assertIn(n, a.scan)
            self.assertNotIn(n, a.cand)
        self.assertIn(reserved[0], a.cand)  # A6: released at once
        self.assertEqual(set(reserved[1:]), {n for n, r in a.reserved.items() if r == "job-9"})
        self.assertEqual(e2.near, {1: 5 << 30})
        self.assertEqual(e2.hb_recv, self.clock() - 30)
        a.check_invariants(self.clock())
        st = e2.dispatch({"op": "status"})
        # the legacy sticky list is a timer list (A10): its line is derived, only the session is remembered
        self.assertEqual(st["counts"], {"lists": 3, "accounts": 2, "sticky": 1, "static": 1, "lines": 1})
        # the static event feed continues
        self.assertEqual(len(e2.dispatch({"op": "bindings", "after": 0})["items"]), 1)

    def test_expired_sticky_is_not_resurrected(self):
        k = ask(self.eng, "netrun-stickyy", port=BASE + 5)
        self.clock.advance(4000)
        e2 = reopen(self, self.eng)
        self.assertNotEqual(ask(e2, "netrun-stickyy", port=BASE + 5).net, k.net)

    def test_ctl_writes_are_durable_before_the_reply(self):
        e = self.eng
        nets = e.dispatch({"op": "reserve_nets", "count": 2, "ref": "durable"})["nets"]
        db = sqlite3.connect(os.path.join(e._test_dir, "radius.db"))
        rows = db.execute("SELECT net, reserved_ref FROM nets ORDER BY net").fetchall()
        self.assertEqual(rows, sorted((n, "durable") for n in nets))
        self.assertEqual(db.execute("SELECT v FROM meta WHERE k='seq'").fetchone()[0], "42")
        db.close()

    def test_bindings_are_batched(self):
        e = self.eng
        ask(e, "netrun-statica", port=BASE + 1)
        db = sqlite3.connect(os.path.join(e._test_dir, "radius.db"))
        self.assertEqual(db.execute("SELECT count(*) FROM bindings").fetchone()[0], 0)
        e.flush()
        self.assertEqual(db.execute("SELECT count(*) FROM bindings").fetchone()[0], 1)
        self.assertEqual(
            db.execute("SELECT op, list_id, slot, reason FROM binding_events").fetchall(),
            [("add", 10, "p1", "first_use")],
        )
        db.close()

    def test_failed_write_is_retried(self):
        e = self.eng
        ask(e, "netrun-statica", port=BASE + 1)
        real = e.store.write
        calls = []

        def flaky(batch):
            calls.append(1)
            if len(calls) == 1:
                raise sqlite3.OperationalError("database or disk is full")
            return real(batch)

        e.store.write = flaky
        self.assertFalse(e.flush())
        self.assertEqual(e.store.write_errors, 1)
        self.assertFalse(e.store.corrupt)
        ask(e, "netrun-statica", port=BASE + 2)
        self.assertTrue(e.flush())
        db = sqlite3.connect(os.path.join(e._test_dir, "radius.db"))
        self.assertEqual(db.execute("SELECT count(*) FROM bindings").fetchone()[0], 2)
        self.assertEqual(db.execute("SELECT count(*) FROM binding_events").fetchone()[0], 2)
        db.close()
        r = e.dispatch({"op": "status"})["db"]
        self.assertEqual(r["writeErrors"], 1)

    def test_ctl_reports_a_failed_commit(self):
        e = self.eng

        def broken(batch):
            raise sqlite3.OperationalError("disk I/O error")

        e.store.write = broken
        r = e.dispatch({"op": "reserve_nets", "count": 1, "ref": "z"})
        self.assertEqual(r["error"], "db_write_failed")

    def test_event_pruning(self):
        e = self.eng
        ask(e, "netrun-statica", port=BASE + 1)
        e.flush()
        self.clock.advance(6 * 86400)
        self.assertEqual(e.prune_events(), 0)
        self.clock.advance(2 * 86400)
        self.assertEqual(e.prune_events(), 1)


class Recovery(unittest.TestCase):
    def test_corrupt_db_moves_aside_with_a_new_epoch(self):
        clock = rtest.FakeClock()
        e = rtest.make_engine(self, clock=clock)
        e.dispatch(
            {
                "op": "snapshot",
                "seq": 3,
                "accounts": [account(1)],
                "lists": [plist(10, "statica", 1, mode="static")],
                "static": [],
            }
        )
        ask(e, "netrun-statica", port=BASE + 1)
        e.flush()
        old_epoch = e.epoch
        d = e._test_dir
        e.store.close()
        path = os.path.join(d, "radius.db")
        with open(path, "r+b") as fh:
            fh.seek(0)
            fh.write(os.urandom(4096))
        e2 = rtest.make_engine(self, clock=clock, path=d, with_facts=False)
        self.assertTrue(e2.db_recovered)
        self.assertNotEqual(e2.epoch, old_epoch)
        self.assertEqual(e2.seq, 0)
        self.assertEqual(len(e2.lists), 0)
        st = e2.dispatch({"op": "status"})
        self.assertTrue(st["dbRecovered"])
        self.assertFalse(st["ready"])
        broken = glob.glob(path + ".broken-*")
        self.assertTrue(broken, os.listdir(d))
        # the agent re-pushes facts and a full snapshot; the DB is usable again
        e2.dispatch({"op": "facts", "facts": rtest.facts()})
        r = e2.dispatch(
            {
                "op": "snapshot",
                "seq": 1,
                "accounts": [account(1)],
                "lists": [plist(10, "statica", 1, mode="static")],
                "static": [],
            }
        )
        self.assertEqual(r["epoch"], e2.epoch)
        self.assertTrue(ask(e2, "netrun-statica", port=BASE + 1).accepted)
        e3 = reopen(self, e2)
        self.assertEqual(e3.epoch, e2.epoch)
        self.assertFalse(e3.db_recovered)

    def test_garbage_file_and_leftover_wal(self):
        d = rtest.tmpdir(self)
        path = os.path.join(d, "radius.db")
        with open(path, "wb") as fh:
            fh.write(b"this is not sqlite" * 100)
        with open(path + "-wal", "wb") as fh:
            fh.write(b"junk")
        e = rtest.make_engine(self, path=d, with_facts=False)
        self.assertTrue(e.db_recovered)
        self.assertTrue(glob.glob(path + ".broken-*"))
        # the new DB is clean and keeps what is written to it
        e.dispatch({"op": "facts", "facts": rtest.facts()})
        e.dispatch({"op": "snapshot", "seq": 8, "accounts": [account(1)], "lists": [], "static": []})
        e2 = reopen(self, e)
        self.assertEqual((e2.epoch, e2.seq, len(e2.accounts)), (e.epoch, 8, 1))
        self.assertFalse(e2.db_recovered)

    def test_unknown_schema_is_recovered(self):
        d = rtest.tmpdir(self)
        path = os.path.join(d, "radius.db")
        db = sqlite3.connect(path)
        db.execute("CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT NOT NULL)")
        db.execute("INSERT INTO meta VALUES ('epoch', '5'), ('schema', '999')")
        db.commit()
        db.close()
        e = rtest.make_engine(self, path=d, with_facts=False)
        self.assertTrue(e.db_recovered)
        self.assertNotEqual(e.epoch, 5)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root ignores directory permissions")
    def test_unwritable_directory_runs_from_memory(self):
        d = rtest.tmpdir(self)
        sub = os.path.join(d, "ro")
        os.mkdir(sub)
        with open(os.path.join(sub, "radius.db"), "wb") as fh:
            fh.write(b"garbage" * 1000)
        os.chmod(sub, stat.S_IRUSR | stat.S_IXUSR)
        self.addCleanup(os.chmod, sub, 0o700)
        st = state.Store(os.path.join(sub, "radius.db"))
        data = st.open()
        self.addCleanup(st.close)
        self.assertTrue(st.recovered)
        self.assertFalse(st.persistent)
        self.assertGreater(data["epoch"], 0)

    def test_new_db_is_not_reported_as_recovered(self):
        e = rtest.make_engine(self, with_facts=False)
        self.assertFalse(e.db_recovered)
        self.assertGreaterEqual(e.epoch, 1 << 32)
        self.assertLess(e.epoch, 1 << 53)


if __name__ == "__main__":
    unittest.main()
