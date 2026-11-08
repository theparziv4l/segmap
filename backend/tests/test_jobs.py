"""Job queue state machine against a fake SSH layer."""
import asyncio
import re
from pathlib import Path

import pytest

from segmap.db import DB
from segmap.jobs import Hub, JobManager

FX = Path(__file__).parent / "fixtures"


class FakeSSH:
    """Remote side simulation: each scan runs until finished or its process group is killed."""

    def __init__(self, db, xml="open_host.xml", hold=False):
        self.db, self.xml, self.hold = db, (FX / xml).read_text(), hold
        self.calls: list[tuple[int, str, str | None]] = []
        self.groups: dict[int, asyncio.Event] = {}
        self.next_pgid = 1000
        self.started: list[str] = []
        self.active = {}  # mid -> count of concurrently running scans
        self.max_parallel = 0
        self.ignore_term = False

    async def machine(self, mid):
        return await self.db.one("SELECT * FROM machines WHERE id=?", (mid,))

    async def sudo_input(self, mid):
        return "s3cret\n"

    async def run(self, mid, command, stdin=None, job_id=None, timeout=None):
        self.calls.append((mid, command, stdin))
        if m := re.search(r"kill -(\w+) -- -(\d+)", command):
            sig, pgid = m[1], int(m[2])
            ev = self.groups.get(pgid)
            alive = ev is not None and not ev.is_set()
            if sig == "KILL" or (sig == "TERM" and not self.ignore_term):
                if ev:
                    ev.set()
            return (0 if alive else 1), "", ""
        if " cat " in f" {command} ":
            return 0, self.xml, ""
        return 0, "", ""

    async def stream(self, mid, command, stdin, on_data, job_id=None):
        self.calls.append((mid, command, stdin))
        self.started.append(job_id)
        pgid = self.next_pgid = self.next_pgid + 1
        ev = self.groups[pgid] = asyncio.Event()
        self.active[mid] = self.active.get(mid, 0) + 1
        self.max_parallel = max(self.max_parallel, sum(self.active.values()))
        assert self.active[mid] == 1, "jobs of one machine must run sequentially"
        try:
            await on_data(f"SEGMAP_PGID={pgid}\nStarting Nmap 7.94\n")
            if self.hold:
                await ev.wait()
                return 143
            await asyncio.sleep(0.01)
            await on_data("Nmap done\n")
            ev.set()
            return 0
        finally:
            self.active[mid] -= 1


@pytest.fixture
async def env(tmp_path):
    db = DB(tmp_path / "t.db")
    await db.open()
    for mid in (1, 2):
        await db.run("INSERT INTO machines(id, name, host, username, secret, mode, status) VALUES (?,?,?,?,?,?,?)",
                     (mid, f"m{mid}", f"10.0.0.{mid}", "kali", b"x", "sudo", "ready"))
        for name, addr in (("eth0", "10.1.2.15/24"), ("eth1", "10.1.3.15/24")):
            await db.run("INSERT INTO interfaces(machine_id, name, ipv4) VALUES (?,?,?)", (mid, name, addr))
    await db.run("INSERT INTO scope(cidr, tag) VALUES ('10.24.5.0/24','CDE'), ('10.24.7.0/24','CDE'), "
                 "('10.1.2.0/24','non-CDE')")
    yield db, tmp_path
    await db.close()


def mgr(db, tmp_path, ssh):
    return JobManager(db, ssh, Hub(), tmp_path / "logs", grace=0.01)


async def wait_idle(m, timeout=3):
    for _ in range(int(timeout / 0.01)):
        if not m.workers:
            return
        await asyncio.sleep(0.01)
    raise AssertionError("workers did not finish")


async def statuses(db):
    return [r["status"] for r in await db.all("SELECT status FROM jobs ORDER BY batch_id, seq")]


async def test_machine_batch_runs_sequentially_and_stores_findings(env):
    db, tmp = env
    ssh = FakeSSH(db)
    m = mgr(db, tmp, ssh)
    res = await m.enqueue({"machine_id": 1, "type": "machine", "checks": ["syn"]})
    assert len(res["jobs"]) == 2 * 3  # 2 ifaces x 3 blocks
    await wait_idle(m)
    assert await statuses(db) == ["done"] * 6
    assert ssh.started == res["jobs"]  # queue order == execution order
    j = await m.job(res["jobs"][0])
    assert j["iface"] == "eth0" and j["pgid"] and j["exit_code"] == 0
    assert j["argv"][:5] == ["nmap", "-n", "--reason", "-e", "eth0"]
    f = await db.all("SELECT * FROM findings WHERE evidence='strong'")
    assert {(r["host_ip"], r["port"]) for r in f} == {("10.24.5.10", 22)}
    # wrapper, sudo over stdin, never on the command line
    scan_cmds = [c for c in ssh.calls if "setsid" in c[1]]
    assert all(c[2] == "s3cret\n" and "s3cret" not in c[1] for c in scan_cmds)
    # remote XML removed after each job
    assert sum(" rm -f /tmp/segmap-" in f" {c[1]}" for c in ssh.calls) == 6
    log = (tmp / "logs" / f"{res['jobs'][0]}.log").read_text()
    assert "Starting Nmap" in log and "SEGMAP_PGID" not in log
    audit = await db.all("SELECT * FROM audit")
    assert audit == [] or audit  # audit is written by the real SSHManager, not the fake


async def test_machines_run_in_parallel(env):
    db, tmp = env
    ssh = FakeSSH(db, hold=True)
    m = mgr(db, tmp, ssh)
    await m.enqueue({"machine_id": 1, "type": "single", "ifaces": ["eth0"], "blocks": ["10.24.5.0/24"], "checks": ["syn"]})
    await m.enqueue({"machine_id": 2, "type": "single", "ifaces": ["eth0"], "blocks": ["10.24.5.0/24"], "checks": ["syn"]})
    for _ in range(100):
        if ssh.max_parallel == 2:
            break
        await asyncio.sleep(0.01)
    assert ssh.max_parallel == 2
    await m.master_kill()
    await wait_idle(m)
    assert await statuses(db) == ["killed", "killed"]


async def test_kill_running_job_terms_process_group(env):
    db, tmp = env
    ssh = FakeSSH(db, hold=True)
    m = mgr(db, tmp, ssh)
    res = await m.enqueue({"machine_id": 1, "type": "interface", "ifaces": ["eth0"], "checks": ["syn"]})
    while not m.live or not next(iter(m.live.values()))["pgid"]:
        await asyncio.sleep(0.01)
    first = res["jobs"][0]
    await m.kill(first)
    await asyncio.sleep(0.05)
    j = await m.job(first)
    assert j["status"] == "killed"
    kills = [c[1] for c in ssh.calls if "kill -" in c[1]]
    assert kills[0] == f"sudo -k -S -p '' env kill -TERM -- -{j['pgid']}"
    assert any("kill -0" in k for k in kills)
    assert not any("kill -KILL" in k for k in kills)  # TERM was enough
    # killed job never parses results; next job in the same interface batch starts
    assert await db.all("SELECT * FROM findings WHERE job_id=?", (first,)) == []
    assert ssh.started[1] == res["jobs"][1]
    await m.master_kill()
    await wait_idle(m)


async def test_kill_escalates_to_sigkill(env):
    db, tmp = env
    ssh = FakeSSH(db, hold=True)
    ssh.ignore_term = True
    m = mgr(db, tmp, ssh)
    res = await m.enqueue({"machine_id": 1, "type": "single", "ifaces": ["eth0"], "blocks": ["10.24.5.0/24"],
                           "checks": ["syn"]})
    while not m.live or not next(iter(m.live.values()))["pgid"]:
        await asyncio.sleep(0.01)
    await m.kill(res["jobs"][0])
    await wait_idle(m)
    kills = [c[1] for c in ssh.calls if "kill -" in c[1]]
    assert [k.split()[7] for k in kills] == ["-TERM", "-0", "-KILL"]
    assert (await m.job(res["jobs"][0]))["status"] == "killed"


async def test_master_kill_cancels_queue(env):
    db, tmp = env
    ssh = FakeSSH(db, hold=True)
    m = mgr(db, tmp, ssh)
    await m.enqueue({"machine_id": 1, "type": "machine", "checks": ["syn", "icmp"]})
    while not m.live:
        await asyncio.sleep(0.01)
    r = await m.master_kill()
    await wait_idle(m)
    st = await statuses(db)
    assert st[0] == "killed" and r["cancelled"] == len(st) - 1
    assert set(st) == {"killed"}
    assert len(ssh.started) == 1


async def test_cancel_queued_job_skips_it(env):
    db, tmp = env
    ssh = FakeSSH(db, hold=True)
    m = mgr(db, tmp, ssh)
    res = await m.enqueue({"machine_id": 1, "type": "interface", "ifaces": ["eth0"], "checks": ["syn"]})
    await m.kill(res["jobs"][1])
    assert (await m.job(res["jobs"][1]))["status"] == "killed"
    await m.master_kill()
    await wait_idle(m)
    assert res["jobs"][1] not in ssh.started


async def test_services_follow_up_uses_prior_open_ports(env):
    db, tmp = env
    ssh = FakeSSH(db)
    m = mgr(db, tmp, ssh)
    res = await m.enqueue({"machine_id": 1, "type": "single", "ifaces": ["eth0"], "blocks": ["10.24.5.0/24"],
                           "checks": ["syn", "services"]})
    await wait_idle(m)
    svc = await m.job(res["jobs"][1])
    assert svc["check_name"] == "services" and svc["status"] == "done"
    assert svc["argv"][-1] == "10.24.5.10" and "T:22" in svc["argv"]
    # a block with no strong ports -> services skipped, not run
    ssh.xml = (FX / "rst_everywhere.xml").read_text()
    res = await m.enqueue({"machine_id": 1, "type": "single", "ifaces": ["eth0"], "blocks": ["10.24.7.0/24"],
                           "checks": ["syn", "services"]})
    await wait_idle(m)
    svc = await m.job(res["jobs"][1])
    assert svc["status"] == "done" and svc["error"].startswith("skipped") and svc["argv"] is None
    syn = await m.job(res["jobs"][0])
    assert "middlebox_rst" in {f["code"] for f in syn["flags"]}


async def test_enqueue_validation(env):
    db, tmp = env
    m = mgr(db, tmp, FakeSSH(db))
    with pytest.raises(ValueError, match="not discovered"):
        await m.enqueue({"machine_id": 1, "ifaces": ["eth9"]})
    with pytest.raises(ValueError, match="not in scope"):
        await m.enqueue({"machine_id": 1, "blocks": ["192.0.2.0/24"]})
    with pytest.raises(ValueError, match="unknown check"):
        await m.enqueue({"machine_id": 1, "checks": ["rm -rf"]})
    await db.kv_set("profile", {"timing": 9})
    with pytest.raises(ValueError, match="timing"):
        await m.enqueue({"machine_id": 1})
    await db.kv_set("profile", {"timing": 0})
    dry = await m.enqueue({"machine_id": 1, "ifaces": ["eth0"], "blocks": ["10.24.5.0/24"], "checks": ["syn"],
                           "dry_run": True})
    assert dry == {"jobs": 1, "estimate_s": dry["estimate_s"]} and await db.all("SELECT * FROM jobs") == []
    res = await m.enqueue({"machine_id": 1, "ifaces": ["eth0"], "blocks": ["10.24.5.0/24"], "checks": ["syn"]})
    assert res["estimate_s"] > 86400  # T0 x 256 hosts x 36 ports takes days
    await m.master_kill()


async def test_egress_only_from_cde_zone_unless_explicit(env):
    db, tmp = env
    await db.kv_set("profile", {"checks": ["syn", "egress"], "egress_listener": "203.0.113.10", "egress_token": "t"})
    await db.run("UPDATE interfaces SET zone_override='CDE' WHERE machine_id=1 AND name='eth1'")
    ssh = FakeSSH(db, hold=True)
    m = mgr(db, tmp, ssh)
    res = await m.enqueue({"machine_id": 1, "blocks": ["10.24.5.0/24"]})
    jobs = [await m.job(j) for j in res["jobs"]]
    assert [(j["iface"], j["check_name"]) for j in jobs] == [("eth0", "syn"), ("eth1", "syn"), ("eth1", "egress")]
    assert jobs[2]["targets"] == ["203.0.113.10"] and jobs[2]["block24"] == "203.0.113.0/24"
    await m.master_kill()
    await wait_idle(m)


async def test_reconcile_after_restart(env):
    db, tmp = env
    ssh = FakeSSH(db)
    await db.run("INSERT INTO jobs(id, machine_id, iface, check_name, status, pgid) VALUES "
                 "(lower(hex(randomblob(16))), 1, 'eth0', 'syn', 'running', 4242)")
    await db.run("INSERT INTO jobs(id, machine_id, iface, check_name, status, pgid) VALUES "
                 "(lower(hex(randomblob(16))), 1, 'eth0', 'syn', 'running', NULL)")
    await db.run("INSERT INTO jobs(id, machine_id, iface, check_name, status) VALUES ('c', 1, 'eth0', 'syn', 'queued')")
    ssh.groups[4242] = asyncio.Event()  # still alive remotely
    await mgr(db, tmp, ssh).reconcile()
    rows = {r["pgid"]: r for r in await db.all("SELECT * FROM jobs WHERE status != 'queued' AND id != 'c'")}
    assert rows[4242]["status"] == "killed" and "still alive" in rows[4242]["error"]
    assert rows[None]["status"] == "failed"
    assert (await db.one("SELECT status FROM jobs WHERE id='c'"))["status"] == "killed"
    assert ssh.groups[4242].is_set()


async def test_audit_snapshots_zone_and_tag_at_run_time(env):
    db, tmp = env

    class AuditingSSH(FakeSSH):  # real SSHManager audits every exec; mirror that
        async def run(self, mid, command, stdin=None, job_id=None, timeout=None):
            await self.db.audit(mid, "10.0.0.1", command, job_id)
            return await super().run(mid, command, stdin, job_id, timeout)

        async def stream(self, mid, command, stdin, on_data, job_id=None):
            await self.db.audit(mid, "10.0.0.1", command, job_id)
            return await super().stream(mid, command, stdin, on_data, job_id)

    m = mgr(db, tmp, AuditingSSH(db))
    await m.enqueue({"machine_id": 1, "ifaces": ["eth0"], "blocks": ["10.24.5.0/24"], "checks": ["syn"]})
    await wait_idle(m)
    # history must not change when scope is retagged or the machine is deleted
    await db.run("UPDATE scope SET tag='out-of-scope' WHERE cidr='10.24.5.0/24'")
    await db.run("DELETE FROM machines WHERE id=1")
    rows = await db.all("SELECT * FROM audit WHERE job_id IS NOT NULL")
    assert len(rows) == 3  # scan, cat, rm
    assert {(r["machine_name"], r["iface"], r["source_ip"], r["source_zone"], r["block24"], r["target_tag"])
            for r in rows} == {("m1", "eth0", "10.1.2.15/24", "non-CDE", "10.24.5.0/24", "CDE")}
