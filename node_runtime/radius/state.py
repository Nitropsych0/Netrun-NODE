"""netrun-radius persistent state: sqlite in WAL mode (/var/lib/netrun-radius/radius.db).

Tables
  meta(k, v)              epoch (random at creation), seq, facts, scan guard, heartbeat
  accounts                one row per account (I5 A, plus local_blocked)
  lists                   one row per list (I5 L)
  bindings                sticky and static bindings, PK (list_id, slot)
  binding_events          static add/release feed (seq AUTOINCREMENT), pruned after 7 days
  rejects                 last reject per list
  nets                    excluded sources per /64 (scan flag, reservation ref, cool-down)
  reservations            reserve_nets / release_nets idempotency records

Binding changes are written in batches (every 100 ms by the writer thread); ctl
operations commit before they reply. A DB that cannot be opened or loaded is
moved aside to radius.db.broken-<ts> and replaced by an empty one under a new
epoch (status dbRecovered). This DB is not backed up: the orchestrator re-pushes
everything after an epoch change.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import sys
import threading
import time

SCHEMA_VERSION = "1"
EVENT_RETENTION_SEC = 7 * 86400

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS accounts(id INTEGER PRIMARY KEY, state TEXT NOT NULL, expires_at REAL,"
    " limit_json TEXT, static_cap INTEGER, sticky_excl_cap INTEGER, trial INTEGER NOT NULL DEFAULT 0,"
    " local_blocked INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS lists(id INTEGER PRIMARY KEY, login TEXT NOT NULL UNIQUE, account_id INTEGER NOT NULL,"
    " pw_salt TEXT NOT NULL, pw_hash TEXT NOT NULL, pw_rev INTEGER NOT NULL, status TEXT NOT NULL,"
    " mode TEXT NOT NULL, ttl_sec INTEGER)",
    "CREATE TABLE IF NOT EXISTS bindings(list_id INTEGER NOT NULL, slot TEXT NOT NULL, kind TEXT NOT NULL,"
    " addr BLOB NOT NULL, net INTEGER NOT NULL, account_id INTEGER NOT NULL, shared INTEGER NOT NULL,"
    " created_at REAL NOT NULL, expires_at REAL, last_used_at REAL, PRIMARY KEY(list_id, slot)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS binding_events(seq INTEGER PRIMARY KEY AUTOINCREMENT, op TEXT NOT NULL,"
    " list_id INTEGER NOT NULL, slot TEXT NOT NULL, addr TEXT NOT NULL, reason TEXT, at REAL NOT NULL)",
    "CREATE INDEX IF NOT EXISTS binding_events_at ON binding_events(at)",
    "CREATE TABLE IF NOT EXISTS rejects(list_id INTEGER PRIMARY KEY, reason TEXT NOT NULL, at REAL NOT NULL,"
    " count INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS nets(net INTEGER PRIMARY KEY, scan INTEGER NOT NULL DEFAULT 0, reserved_ref TEXT,"
    " reserved_at REAL, cooldown_until REAL)",
    "CREATE TABLE IF NOT EXISTS reservations(ref TEXT PRIMARY KEY, kind TEXT NOT NULL, nets TEXT NOT NULL,"
    " until REAL, at REAL NOT NULL)",
)


def new_epoch() -> int:
    """Random epoch, safe as a JavaScript number (< 2**53) and never small."""
    return (1 << 32) + secrets.randbelow((1 << 53) - (1 << 32))


def log(msg: str):
    print("netrun-radius: " + msg, file=sys.stderr, flush=True)


class Batch:
    """Everything one flush writes, in one transaction."""

    __slots__ = ("meta", "accounts", "lists", "bindings", "events", "rejects", "nets", "refs")

    def __init__(self):
        self.meta = {}  # k -> str
        self.accounts = {}  # id -> row tuple | None (delete)
        self.lists = {}  # id -> row tuple | None
        self.bindings = {}  # (list_id, slot) -> row tuple | None
        self.events = []  # (op, list_id, slot, addr_str, reason, at)
        self.rejects = {}  # list_id -> (reason, at, count) | None
        self.nets = {}  # net -> (scan, ref, reserved_at, cooldown_until) | None
        self.refs = {}  # ref -> (kind, nets_json, until, at) | None

    def empty(self) -> bool:
        return not (
            self.meta
            or self.accounts
            or self.lists
            or self.bindings
            or self.events
            or self.rejects
            or self.nets
            or self.refs
        )

    def merge_older(self, older: Batch):
        """Put back the parts of a failed older batch that this batch does not supersede."""
        for name in ("meta", "accounts", "lists", "bindings", "rejects", "nets", "refs"):
            mine = getattr(self, name)
            for k, v in getattr(older, name).items():
                if k not in mine:
                    mine[k] = v
        self.events = older.events + self.events


class Store:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.RLock()
        self.conn = None
        self.recovered = False
        self.broken_path = None
        self.persistent = True
        self.write_errors = 0
        self.last_write_error = None
        self.corrupt = False

    # ---- open / recover ------------------------------------------------------------

    def open(self) -> dict:
        """Open (or create) the DB and load everything. Never raises for DB problems."""
        try:
            return self._open_and_load()
        except (sqlite3.Error, OSError, ValueError, TypeError) as e:
            log("state DB unusable (%s: %s); moving it aside" % (type(e).__name__, e))
            self._close()
        self.recovered = True
        self.broken_path = self._move_aside()
        try:
            return self._open_and_load()
        except (sqlite3.Error, OSError, ValueError, TypeError) as e:
            log("cannot create a new state DB (%s); running from memory" % e)
            self._close()
        self.persistent = False
        return self._open_and_load(memory=True)

    def _close(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except sqlite3.Error:
                pass
        self.conn = None

    def _move_aside(self):
        ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        dest = "%s.broken-%s" % (self.path, ts)
        moved = None
        for suffix in ("", "-wal", "-shm", "-journal"):
            src = self.path + suffix
            if os.path.lexists(src):
                try:
                    os.replace(src, dest + suffix)
                    moved = dest
                except OSError as e:
                    log("cannot move %s aside: %s" % (src, e))
                    try:
                        os.unlink(src)
                    except OSError:
                        pass
        return moved

    def _open_and_load(self, memory: bool = False) -> dict:
        target = ":memory:" if memory else self.path
        if not memory:
            d = os.path.dirname(self.path)
            if d:
                os.makedirs(d, mode=0o700, exist_ok=True)
        conn = sqlite3.connect(target, isolation_level=None, check_same_thread=False, timeout=5.0)
        self.conn = conn
        conn.execute("PRAGMA busy_timeout=5000")
        if not memory:
            mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise sqlite3.DatabaseError("journal_mode=%s" % mode)
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("BEGIN IMMEDIATE")
        try:
            for stmt in SCHEMA:
                conn.execute(stmt)
            meta = dict(conn.execute("SELECT k, v FROM meta").fetchall())
            if "epoch" not in meta:
                meta["epoch"] = str(new_epoch())
                meta["seq"] = "0"
                meta["schema"] = SCHEMA_VERSION
                meta["created_at"] = repr(time.time())
                conn.executemany("INSERT OR REPLACE INTO meta(k, v) VALUES (?, ?)", list(meta.items()))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        if meta.get("schema") != SCHEMA_VERSION:
            raise ValueError("unknown schema %r" % meta.get("schema"))
        data = {
            "meta": meta,
            "epoch": int(meta["epoch"]),
            "seq": int(meta.get("seq", "0")),
            "accounts": conn.execute(
                "SELECT id, state, expires_at, limit_json, static_cap, sticky_excl_cap, trial, local_blocked FROM accounts"
            ).fetchall(),
            "lists": conn.execute(
                "SELECT id, login, account_id, pw_salt, pw_hash, pw_rev, status, mode, ttl_sec FROM lists"
            ).fetchall(),
            "bindings": conn.execute(
                "SELECT list_id, slot, kind, addr, net, account_id, shared, created_at, expires_at, last_used_at FROM bindings"
            ).fetchall(),
            "rejects": conn.execute("SELECT list_id, reason, at, count FROM rejects").fetchall(),
            "nets": conn.execute("SELECT net, scan, reserved_ref, reserved_at, cooldown_until FROM nets").fetchall(),
            "refs": conn.execute("SELECT ref, kind, nets, until, at FROM reservations").fetchall(),
        }
        for k in ("facts", "scan_guard", "heartbeat"):
            if k in meta:
                data[k] = json.loads(meta[k])
        return data

    # ---- writes --------------------------------------------------------------------

    def write(self, batch: Batch):
        """Write one batch in one transaction. The caller holds self.lock."""
        conn = self.conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            if batch.meta:
                conn.executemany("INSERT OR REPLACE INTO meta(k, v) VALUES (?, ?)", list(batch.meta.items()))
            self._upsert_delete(
                conn,
                batch.accounts,
                "INSERT OR REPLACE INTO accounts(id, state, expires_at, limit_json, static_cap, sticky_excl_cap, trial,"
                " local_blocked) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                "DELETE FROM accounts WHERE id = ?",
            )
            self._upsert_delete(
                conn,
                batch.lists,
                "INSERT OR REPLACE INTO lists(id, login, account_id, pw_salt, pw_hash, pw_rev, status, mode, ttl_sec)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                "DELETE FROM lists WHERE id = ?",
            )
            if batch.bindings:
                ups = [row for row in batch.bindings.values() if row is not None]
                dels = [k for k, row in batch.bindings.items() if row is None]
                if dels:
                    conn.executemany("DELETE FROM bindings WHERE list_id = ? AND slot = ?", dels)
                if ups:
                    conn.executemany(
                        "INSERT OR REPLACE INTO bindings(list_id, slot, kind, addr, net, account_id, shared, created_at,"
                        " expires_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        ups,
                    )
            if batch.events:
                conn.executemany(
                    "INSERT INTO binding_events(op, list_id, slot, addr, reason, at) VALUES (?, ?, ?, ?, ?, ?)",
                    batch.events,
                )
            if batch.rejects:
                ups = [(k,) + v for k, v in batch.rejects.items() if v is not None]
                dels = [(k,) for k, v in batch.rejects.items() if v is None]
                if dels:
                    conn.executemany("DELETE FROM rejects WHERE list_id = ?", dels)
                if ups:
                    conn.executemany(
                        "INSERT OR REPLACE INTO rejects(list_id, reason, at, count) VALUES (?, ?, ?, ?)", ups
                    )
            if batch.nets:
                ups = [(k,) + v for k, v in batch.nets.items() if v is not None]
                dels = [(k,) for k, v in batch.nets.items() if v is None]
                if dels:
                    conn.executemany("DELETE FROM nets WHERE net = ?", dels)
                if ups:
                    conn.executemany(
                        "INSERT OR REPLACE INTO nets(net, scan, reserved_ref, reserved_at, cooldown_until)"
                        " VALUES (?, ?, ?, ?, ?)",
                        ups,
                    )
            if batch.refs:
                ups = [(k,) + v for k, v in batch.refs.items() if v is not None]
                dels = [(k,) for k, v in batch.refs.items() if v is None]
                if dels:
                    conn.executemany("DELETE FROM reservations WHERE ref = ?", dels)
                if ups:
                    conn.executemany(
                        "INSERT OR REPLACE INTO reservations(ref, kind, nets, until, at) VALUES (?, ?, ?, ?, ?)", ups
                    )
            conn.execute("COMMIT")
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

    @staticmethod
    def _upsert_delete(conn, rows: dict, up_sql: str, del_sql: str):
        if not rows:
            return
        dels = [(k,) for k, v in rows.items() if v is None]
        ups = [v for v in rows.values() if v is not None]
        if dels:
            conn.executemany(del_sql, dels)
        if ups:
            conn.executemany(up_sql, ups)

    # ---- reads ---------------------------------------------------------------------

    def events_after(self, after: int, limit: int) -> list:
        with self.lock:
            return self.conn.execute(
                "SELECT seq, op, list_id, slot, addr, reason, at FROM binding_events WHERE seq > ? ORDER BY seq LIMIT ?",
                (after, limit),
            ).fetchall()

    def last_event_seq(self) -> int:
        with self.lock:
            row = self.conn.execute("SELECT max(seq) FROM binding_events").fetchone()
        return int(row[0] or 0)

    def prune_events(self, before: float) -> int:
        with self.lock:
            cur = self.conn.execute("DELETE FROM binding_events WHERE at < ?", (before,))
            return cur.rowcount

    def close(self):
        with self.lock:
            self._close()
