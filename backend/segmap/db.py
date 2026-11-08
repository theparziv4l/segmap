"""SQLite via aiosqlite, plain SQL. JSON lives in TEXT columns."""
import getpass
import json
from datetime import datetime, timezone

import aiosqlite

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS machines(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 22,
  username TEXT NOT NULL, secret BLOB NOT NULL, host_key TEXT, pending_key TEXT, mode TEXT,
  prereq TEXT, facts TEXT, status TEXT NOT NULL DEFAULT 'new', error TEXT,
  created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS interfaces(
  id INTEGER PRIMARY KEY, machine_id INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
  name TEXT NOT NULL, ipv4 TEXT, mac TEXT, state TEXT, hidden INTEGER NOT NULL DEFAULT 0, zone_override TEXT,
  UNIQUE(machine_id, name));
CREATE TABLE IF NOT EXISTS tags(name TEXT PRIMARY KEY, color TEXT NOT NULL, builtin INTEGER NOT NULL DEFAULT 0,
  rank INTEGER NOT NULL DEFAULT 50);
CREATE TABLE IF NOT EXISTS scope(id INTEGER PRIMARY KEY, cidr TEXT NOT NULL UNIQUE,
  tag TEXT NOT NULL REFERENCES tags(name), note TEXT);
CREATE TABLE IF NOT EXISTS batches(id INTEGER PRIMARY KEY, type TEXT NOT NULL, machine_id INTEGER,
  created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS jobs(
  id TEXT PRIMARY KEY, batch_id INTEGER, seq INTEGER, machine_id INTEGER REFERENCES machines(id) ON DELETE CASCADE,
  iface TEXT, check_name TEXT, block24 TEXT, targets TEXT, params TEXT, argv TEXT, command TEXT,
  status TEXT NOT NULL, pgid INTEGER, exit_code INTEGER, queued_at TEXT, started_at TEXT, finished_at TEXT,
  flags TEXT, error TEXT);
CREATE INDEX IF NOT EXISTS jobs_q ON jobs(machine_id, status, batch_id, seq);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY, job_id TEXT REFERENCES jobs(id) ON DELETE CASCADE, machine_id INTEGER, iface TEXT,
  host_ip TEXT, block24 TEXT, check_name TEXT, protocol TEXT, port INTEGER, state TEXT, reason TEXT,
  reason_ip TEXT, ttl INTEGER, service TEXT, evidence TEXT, detail TEXT, seen_at TEXT);
CREATE INDEX IF NOT EXISTS findings_edge ON findings(machine_id, iface, block24);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts TEXT, actor TEXT, machine_id INTEGER,
  target_host TEXT, job_id TEXT, command TEXT);
CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT);
"""

# Columns added after the first release (TEXT, add-only migration in open()).
# jobs/audit: run-time snapshots, so audit evidence shows zone/tag/IP as they were when the command ran and
# survives later scope retagging, interface changes and machine deletion (jobs cascade-delete with machines).
# machines.paused: NULL = queue runs, otherwise why it is paused (user, connection lost, backend restart).
ADD_COLS = {
    "machines": ("paused",),
    "jobs": ("source_ip", "source_zone", "target_tag"),
    "audit": ("machine_name", "iface", "source_ip", "source_zone", "check_name", "block24", "target_tag", "targets"),
}
BUILTIN_TAGS = [("CDE", "#e5484d", 0), ("connected-to", "#f76b15", 1), ("non-CDE", "#3e63dd", 2),
                ("out-of-scope", "#8b8d98", 3)]
ACTOR = getpass.getuser()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def dumps(v) -> str:
    return json.dumps(v, separators=(",", ":"))


def loads(v, default=None):
    return json.loads(v) if v else default


class DB:
    def __init__(self, path):
        self.path = path
        self.conn: aiosqlite.Connection | None = None

    async def open(self):
        self.conn = await aiosqlite.connect(self.path)
        self.conn.row_factory = aiosqlite.Row
        await self.conn.executescript(SCHEMA)
        for table, cols in ADD_COLS.items():  # add-only migration for DBs created before these columns
            have = {r["name"] for r in await self.all(f"PRAGMA table_info({table})")}
            for c in cols:
                if c not in have:
                    await self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {c} TEXT")
        await self.conn.executemany("INSERT OR IGNORE INTO tags(name, color, builtin, rank) VALUES (?,?,1,?)",
                                    BUILTIN_TAGS)
        await self.conn.commit()

    async def close(self):
        await self.conn.close()

    async def all(self, sql, args=()) -> list[dict]:
        async with self.conn.execute(sql, args) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def one(self, sql, args=()) -> dict | None:
        async with self.conn.execute(sql, args) as cur:
            r = await cur.fetchone()
            return dict(r) if r else None

    async def run(self, sql, args=()) -> int:
        cur = await self.conn.execute(sql, args)
        await self.conn.commit()
        return cur.lastrowid

    async def many(self, sql, rows):
        await self.conn.executemany(sql, rows)
        await self.conn.commit()

    async def kv_get(self, key, default=None):
        r = await self.one("SELECT value FROM kv WHERE key=?", (key,))
        return loads(r["value"]) if r else default

    async def kv_set(self, key, value):
        await self.run("INSERT INTO kv(key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                       (key, dumps(value)))

    async def audit(self, machine_id, target_host, command, job_id=None):
        """Copies the job's run-time snapshot into the audit row (NULLs for non-job commands)."""
        await self.run(
            "INSERT INTO audit(ts, actor, machine_id, target_host, job_id, command, machine_name, iface, source_ip, "
            "source_zone, check_name, block24, target_tag, targets) "
            "SELECT ?,?,?,?,?,?, (SELECT name FROM machines WHERE id=?), j.iface, j.source_ip, j.source_zone, "
            "j.check_name, j.block24, j.target_tag, j.targets FROM (SELECT 1) LEFT JOIN jobs j ON j.id=?",
            (now(), ACTOR, machine_id, target_host, job_id, command, machine_id, job_id))
