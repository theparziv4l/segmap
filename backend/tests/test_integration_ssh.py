"""End-to-end over a real SSH connection (in-process asyncssh server that runs commands with local sh)
and real nmap. Skipped unless SEGMAP_IT=1 and local nmap can open raw sockets (root/cap/sudo-less).

Sends a few probes to TEST-NET-1 (192.0.2.0/30) only."""
import asyncio
import os
import shutil
import subprocess

import asyncssh
import pytest

from segmap.crypto import Vault
from segmap.db import DB
from segmap.jobs import Hub, JobManager
from segmap.ssh import SSHManager, probe

pytestmark = pytest.mark.skipif(os.environ.get("SEGMAP_IT") != "1" or not shutil.which("nmap"),
                                reason="set SEGMAP_IT=1 to run against local nmap")


class _Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return password == "pw"


async def _handle(process):
    local = await asyncio.create_subprocess_shell(process.command, stdin=asyncio.subprocess.PIPE,
                                                  stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    await process.redirect(stdin=local.stdin, stdout=local.stdout, stderr=local.stderr)
    process.exit(await local.wait())
    await process.wait_closed()


@pytest.fixture
async def stack(tmp_path):
    key = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.create_server(_Server, "127.0.0.1", 0, server_host_keys=[key], process_factory=_handle)
    port = server.sockets[0].getsockname()[1]
    db = DB(tmp_path / "it.db")
    await db.open()
    vault = Vault(Vault.__init__.__globals__["Fernet"].generate_key())
    mid = await db.run("INSERT INTO machines(name, host, port, username, secret) VALUES (?,?,?,?,?)",
                       ("local", "127.0.0.1", port, os.environ.get("USER", "kali"),
                        vault.seal({"password": "pw", "sudo_password": "not-the-sudo-password"})))
    ssh = SSHManager(db, vault)
    jobs = JobManager(db, ssh, Hub(), tmp_path / "logs", grace=1.0)
    yield db, ssh, jobs, mid, key
    for c in list(ssh.conns.values()):
        c.close()
    server.close()
    await db.close()


async def _connect(db, ssh, mid, key):
    info = await ssh.fetch_host_key(mid)
    assert info["fingerprint"] == key.get_fingerprint("sha256") and not info["trusted"]
    await ssh.trust(mid, info["fingerprint"])
    p = await probe(ssh, mid)
    m = await ssh.machine(mid)
    if not m["mode"]:
        pytest.skip(f"local nmap cannot do raw sockets: {p['errors']}")
    return p


async def _wait(jobs, timeout=120):
    for _ in range(timeout * 10):
        if not jobs.workers:
            return
        await asyncio.sleep(0.1)
    raise AssertionError("timeout")


async def test_e2e_testnet_zero_strong_and_audit(stack):
    db, ssh, jobs, mid, key = stack
    p = await _connect(db, ssh, mid, key)
    assert p["nmap_version"].startswith("Nmap")
    ifaces = await db.all("SELECT * FROM interfaces WHERE machine_id=?", (mid,))
    names = {i["name"] for i in ifaces}
    assert "lo" not in names and names
    iface = sorted(names)[0]
    await db.run("INSERT INTO scope(cidr, tag) VALUES ('192.0.2.0/30', 'out-of-scope')")
    await db.kv_set("profile", {"timing": 4, "tcp_ports": "22,80,443", "advanced": {"max_retries": 1}})
    res = await jobs.enqueue({"machine_id": mid, "ifaces": [iface], "checks": ["syn", "icmp"]})
    await _wait(jobs)
    for jid in res["jobs"]:
        j = await jobs.job(jid)
        assert j["status"] == "done", j
        assert j["pgid"] and j["argv"][0] == "nmap"
    strong = await db.all("SELECT * FROM findings WHERE evidence='strong'")
    assert strong == []  # acceptance: nothing in TEST-NET-1 counts as reachable
    audit = [a["command"] for a in await db.all("SELECT command FROM audit")]
    assert any("setsid -w sh -c" in a for a in audit) and any(" rm -f /tmp/segmap-" in f" {a}" for a in audit)
    assert not any("not-the-sudo-password" in a for a in audit)
    assert not list((p for p in os.listdir("/tmp") if p.startswith("segmap-") and p[7:-4] in res["jobs"]))


async def test_e2e_kill_really_terminates_remote_nmap(stack):
    db, ssh, jobs, mid, key = stack
    await _connect(db, ssh, mid, key)
    iface = sorted(r["name"] for r in await db.all("SELECT name FROM interfaces WHERE machine_id=?", (mid,)))[0]
    await db.run("INSERT INTO scope(cidr, tag) VALUES ('192.0.2.0/30', 'out-of-scope')")
    await db.kv_set("profile", {"timing": 1, "tcp_ports": "1-1000"})  # T1: would take hours
    res = await jobs.enqueue({"machine_id": mid, "ifaces": [iface], "checks": ["syn"]})
    jid = res["jobs"][0]
    for _ in range(200):
        live = jobs.live.get(jid)
        if live and live["pgid"]:
            break
        await asyncio.sleep(0.05)
    pgid = jobs.live[jid]["pgid"]
    assert subprocess.run(["pgrep", "-g", str(pgid)], capture_output=True).returncode == 0  # nmap alive
    await jobs.kill(jid)
    await _wait(jobs, 30)
    assert (await jobs.job(jid))["status"] == "killed"
    assert subprocess.run(["pgrep", "-g", str(pgid)], capture_output=True).returncode == 1  # group gone
