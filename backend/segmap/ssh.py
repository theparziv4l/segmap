"""SSH layer: TOFU host keys, connections, audited exec, prerequisite check, interface discovery."""
import asyncio
import json
import re

import asyncssh

from . import commands as cmd
from .db import DB, dumps


class HostKeyError(Exception):
    pass


class SSHManager:
    """All remote execution goes through run()/stream(); both write the audit log."""

    def __init__(self, db: DB, vault):
        self.db, self.vault = db, vault
        self.conns: dict[int, asyncssh.SSHClientConnection] = {}
        self.locks: dict[int, asyncio.Lock] = {}

    async def machine(self, mid: int) -> dict:
        m = await self.db.one("SELECT * FROM machines WHERE id=?", (mid,))
        if not m:
            raise KeyError(f"machine {mid} not found")
        return m

    async def secret(self, mid: int) -> dict:
        return self.vault.open((await self.machine(mid))["secret"])

    async def sudo_input(self, mid: int) -> str | None:
        m = await self.machine(mid)
        if m["mode"] != "sudo":
            return None
        s = self.vault.open(m["secret"])
        return (s.get("sudo_password") or s.get("password") or "") + "\n"

    # ---- host keys (trust on first use) ----
    async def fetch_host_key(self, mid: int) -> dict:
        m = await self.machine(mid)
        key = await asyncssh.get_server_host_key(m["host"], m["port"], config=None)
        if key is None:
            raise HostKeyError("server presented no host key")
        pub = key.export_public_key("openssh").decode().strip()
        fp = key.get_fingerprint("sha256")
        known = m["host_key"]
        changed = bool(known) and known.split()[:2] != pub.split()[:2]
        if not known or changed:
            await self.db.run("UPDATE machines SET pending_key=?, status=?, error=? WHERE id=?",
                              (pub, "hostkey_changed" if changed else "hostkey_pending",
                               ("HOST KEY CHANGED - possible MITM. Old key: " + fingerprint(known)) if changed else None,
                               mid))
        return {"fingerprint": fp, "changed": changed, "trusted": bool(known) and not changed}

    async def trust(self, mid: int, fp: str):
        m = await self.machine(mid)
        if not m["pending_key"] or fingerprint(m["pending_key"]) != fp:
            raise HostKeyError("fingerprint does not match the pending host key; fetch it again")
        await self.db.run("UPDATE machines SET host_key=pending_key, pending_key=NULL, status='disconnected', "
                          "error=NULL WHERE id=?", (mid,))
        await self.disconnect(mid)

    # ---- connections ----
    async def connect(self, mid: int) -> asyncssh.SSHClientConnection:
        lock = self.locks.setdefault(mid, asyncio.Lock())
        async with lock:
            c = self.conns.get(mid)
            if c is not None and not c.is_closed():
                return c
            m = await self.machine(mid)
            if not m["host_key"]:
                raise HostKeyError("host key not trusted yet")
            s = self.vault.open(m["secret"])
            keys = [asyncssh.import_private_key(s["key"], s.get("passphrase") or None)] if s.get("key") else None
            try:
                c = await asyncssh.connect(
                    m["host"], port=m["port"], username=m["username"], password=s.get("password") or None,
                    client_keys=keys, known_hosts=([asyncssh.import_public_key(m["host_key"])], [], []),
                    agent_path=None, config=None, keepalive_interval=30)
            except asyncssh.HostKeyNotVerifiable:
                await self.fetch_host_key(mid)
                raise HostKeyError("HOST KEY CHANGED or not verifiable - refusing to connect") from None
            self.conns[mid] = c
            return c

    async def disconnect(self, mid: int):
        c = self.conns.pop(mid, None)
        if c:
            c.close()

    async def run(self, mid: int, command: str, stdin: str | None = None, job_id: str | None = None,
                  timeout: float | None = 120) -> tuple[int, str, str]:
        m = await self.machine(mid)
        await self.db.audit(mid, m["host"], command, job_id)
        c = await self.connect(mid)
        r = await c.run(command, input=stdin, check=False, timeout=timeout)
        return (r.exit_status if r.exit_status is not None else -1), r.stdout or "", r.stderr or ""

    async def stream(self, mid: int, command: str, stdin: str | None, on_data, job_id: str | None = None) -> int:
        m = await self.machine(mid)
        await self.db.audit(mid, m["host"], command, job_id)
        c = await self.connect(mid)
        async with c.create_process(command, stderr=asyncssh.STDOUT) as proc:
            if stdin:
                proc.stdin.write(stdin)
            proc.stdin.write_eof()
            while True:
                data = await proc.stdout.read(8192)
                if not data:
                    break
                await on_data(data)
            await proc.wait()
            return proc.exit_status if proc.exit_status is not None else -1


def fingerprint(pub: str | None) -> str:
    return asyncssh.import_public_key(pub).get_fingerprint("sha256") if pub else ""


# ---------- prerequisite check & discovery ----------
def parse_prereq(out: str) -> dict:
    kv = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    return {"uid": int(kv.get("uid") or -1), "nmap": kv.get("nmap", ""), "nmap_version": kv.get("nmapver", ""),
            "ip": kv.get("ip", ""), "setsid": kv.get("setsid", ""), "caps": kv.get("caps", "")}


def decide_mode(p: dict, sudo_ok: bool) -> tuple[str | None, list[str]]:
    errors = [f"{tool} not found on PATH" for tool in ("nmap", "ip", "setsid") if not p[tool]]
    if p["uid"] == 0:
        mode = "root"
    elif sudo_ok:
        mode = "sudo"
    elif "cap_net_raw" in p["caps"]:
        mode = "cap"
    else:
        mode = None
        errors.append("no root, no working sudo and nmap lacks cap_net_raw: raw sockets (-sS, ICMP) impossible")
    return (mode if not errors else None), errors


def parse_ifaces_json(text: str) -> list[dict]:
    out = []
    for i in json.loads(text):
        v4 = [a for a in i.get("addr_info", []) if a.get("family") == "inet"]
        out.append({"name": i["ifname"], "mac": i.get("address"), "state": i.get("operstate", "UNKNOWN"),
                    "ipv4": f"{v4[0]['local']}/{v4[0]['prefixlen']}" if v4 else None})
    return [i for i in out if usable(i)]


def parse_ifaces_text(text: str) -> list[dict]:
    """Fallback for `ip -o addr show; ip -o link show`."""
    found: dict[str, dict] = {}
    for line in text.splitlines():
        m = re.match(r"\d+:\s+([^:\s@]+)(?:@\S+)?:?\s+(.*)", line)
        if not m:
            continue
        name, rest = m.groups()
        i = found.setdefault(name, {"name": name, "mac": None, "state": "UNKNOWN", "ipv4": None})
        if a := re.search(r"\binet (\d+\.\d+\.\d+\.\d+/\d+)", rest):
            i["ipv4"] = i["ipv4"] or a[1]
        if s := re.search(r"\bstate (\S+)", rest):
            i["state"] = s[1]
        if mac := re.search(r"link/ether ([0-9a-f:]{17})", rest):
            i["mac"] = mac[1]
    return [i for i in found.values() if usable(i)]


def usable(i: dict) -> bool:
    return i["name"] != "lo" and bool(i["ipv4"]) and i["state"] != "DOWN" and bool(cmd.IFACE_RE.match(i["name"]))


async def probe(ssh: SSHManager, mid: int) -> dict:
    """Connect-time checks: prerequisites, privilege mode, interfaces, routes/neighbours."""
    db = ssh.db
    rc, out, err = await ssh.run(mid, cmd.PREREQ_CMD)
    p = parse_prereq(out)
    sudo_ok = False
    if p["uid"] != 0:
        s = await ssh.secret(mid)
        pw = s.get("sudo_password") or s.get("password") or ""
        rc, _, _ = await ssh.run(mid, cmd.SUDO_TEST_CMD, stdin=pw + "\n", timeout=20)
        sudo_ok = rc == 0
    mode, errors = decide_mode(p, sudo_ok)
    p.update(sudo_ok=sudo_ok, errors=errors)

    rc, out, _ = await ssh.run(mid, cmd.IFACES_JSON_CMD)
    try:
        ifaces = parse_ifaces_json(out) if rc == 0 else None
    except (ValueError, KeyError):
        ifaces = None
    if ifaces is None:
        _, out, _ = await ssh.run(mid, cmd.IFACES_TEXT_CMD)
        ifaces = parse_ifaces_text(out)

    facts = {}
    for k, c in (("routes", cmd.ROUTES_CMD), ("neighbors", cmd.NEIGH_CMD)):
        rc, out, _ = await ssh.run(mid, c)
        try:
            facts[k] = json.loads(out) if rc == 0 else []
        except ValueError:
            facts[k] = []

    names = [i["name"] for i in ifaces]
    for i in ifaces:
        await db.run("INSERT INTO interfaces(machine_id, name, ipv4, mac, state) VALUES (?,?,?,?,?) "
                     "ON CONFLICT(machine_id, name) DO UPDATE SET ipv4=excluded.ipv4, mac=excluded.mac, "
                     "state=excluded.state", (mid, i["name"], i["ipv4"], i["mac"], i["state"]))
    await db.run(f"DELETE FROM interfaces WHERE machine_id=? AND name NOT IN ({','.join('?' * len(names))})",
                 (mid, *names))
    await db.run("UPDATE machines SET mode=?, prereq=?, facts=?, status=?, error=? WHERE id=?",
                 (mode, dumps(p), dumps(facts), "ready" if mode else "error", "; ".join(errors) or None, mid))
    return p
