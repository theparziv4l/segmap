"""Job queue: one sequential worker per machine, machines in parallel; streaming; kill; reconcile."""
import asyncio
import ipaddress as ip
import re
import shlex
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

from . import commands as cmd
from . import targets as tg
from .checks import BLOCK_ORDER, REGISTRY, process
from .db import DB, dumps, loads, now

PGID_RE = re.compile(r"SEGMAP_PGID=(\d+)\r?\n")
# rough seconds per (host x port) probe, per -T template; ponytail: crude, good enough to warn on T0/T1
PER_PROBE = {0: 300.0, 1: 15.0, 2: 0.4, 3: 0.01, 4: 0.005, 5: 0.003}
DEFAULT_PROFILE = {
    "timing": 3, "checks": ["syn", "icmp"], "tcp_ports": cmd.DEFAULT_TCP_PORTS, "udp_ports": cmd.DEFAULT_UDP_PORTS,
    "advanced": {"max_rate": None, "max_retries": None, "host_timeout": None},
    "egress_listener": "", "egress_ports": "1-1024", "egress_token": "",
}


def block_of(addr: str) -> str:
    return str(ip.IPv4Network(f"{addr}/24", strict=False))


class Hub:
    def __init__(self):
        self.clients = set()

    async def send(self, msg: dict):
        for ws in list(self.clients):
            try:
                await ws.send_json(msg)
            except Exception:
                self.clients.discard(ws)


class JobManager:
    def __init__(self, db: DB, ssh, hub: Hub, log_dir: Path, grace: float = 3.0):
        self.db, self.ssh, self.hub, self.log_dir, self.grace = db, ssh, hub, log_dir, grace
        self.workers: dict[int, asyncio.Task] = {}
        self.live: dict[str, dict] = {}   # job_id -> {"pgid", "kill", "task", "machine_id"}
        log_dir.mkdir(parents=True, exist_ok=True)

    # ---------- enqueue ----------
    async def profile(self) -> dict:
        return {**DEFAULT_PROFILE, **(await self.db.kv_get("profile", {}))}

    async def scope(self):
        rows = await self.db.all("SELECT cidr, tag FROM scope")
        return [(ip.IPv4Network(r["cidr"]), r["tag"]) for r in rows]

    async def iface_zones(self, mid: int, scope=None) -> dict[str, str | None]:
        scope = scope if scope is not None else await self.scope()
        rows = await self.db.all("SELECT name, ipv4, zone_override FROM interfaces WHERE machine_id=?", (mid,))
        return {r["name"]: r["zone_override"] or (tg.zone_for_ip(r["ipv4"].split("/")[0], scope) if r["ipv4"] else None)
                for r in rows}

    async def enqueue(self, spec: dict) -> dict:
        """spec: machine_id, type (single|interface|machine), ifaces?, blocks?, checks?"""
        mid = int(spec["machine_id"])
        m = await self.ssh.machine(mid)
        if not m["mode"]:
            raise ValueError("machine not ready (connect and pass the prerequisite check first)")
        prof = await self.profile()
        scope = await self.scope()
        zones = await self.iface_zones(mid, scope)
        visible = [r["name"] for r in await self.db.all(
            "SELECT name FROM interfaces WHERE machine_id=? AND hidden=0 ORDER BY name", (mid,))]
        ifaces = spec.get("ifaces") or visible
        for i in ifaces:
            if i not in zones:
                raise ValueError(f"interface {i!r} not discovered on this machine")
        bmap = tg.block_tags(scope)
        blocks = [ip.IPv4Network(b) for b in spec.get("blocks") or []] or sorted(bmap)
        for b in blocks:
            if b not in bmap:
                raise ValueError(f"{b} is not in scope")
        explicit = spec.get("checks")
        checks = explicit or prof["checks"]
        for c in checks:
            if c not in REGISTRY:
                raise ValueError(f"unknown check {c!r}")
        params = {k: prof[k] for k in ("timing", "tcp_ports", "udp_ports", "advanced", "egress_listener",
                                       "egress_ports", "egress_token")}
        params["advanced"] = {k: v for k, v in (params["advanced"] or {}).items() if v not in (None, "")}
        scope_nets = [n for n, _ in scope]

        plan = []
        for iface in ifaces:
            for b in blocks:
                targets = tg.targets_in_block(b, scope_nets)
                plan += [(iface, c, str(b), targets) for c in BLOCK_ORDER if c in checks]
            if "egress" in checks and (explicit or zones.get(iface) == "CDE"):
                lst = cmd.check_ip(params["egress_listener"]) if params["egress_listener"] else None
                if not lst:
                    raise ValueError("egress check needs a listener IP in the scan profile")
                plan.append((iface, "egress", block_of(lst), [lst]))
        if not plan:
            raise ValueError("nothing to run: no interfaces, blocks or checks selected")

        # validate every command up front (services is built at run time from earlier results)
        known = set(zones)
        for iface, c, b, targets in plan:
            if c != "services":
                REGISTRY[c].build({**params, "iface": iface, "targets": targets, "job_id": "0" * 32,
                                   "known_ifaces": known, "privileged": m["mode"] == "cap"})

        if spec.get("dry_run"):
            return {"jobs": len(plan), "estimate_s": estimate(plan, params)}
        batch = await self.db.run("INSERT INTO batches(type, machine_id) VALUES (?,?)", (spec.get("type", "single"), mid))
        ts = now()
        rows = [(uuid.uuid4().hex, batch, seq, mid, iface, c, b, dumps(targets), dumps(params), "queued", ts)
                for seq, (iface, c, b, targets) in enumerate(plan)]
        await self.db.many("INSERT INTO jobs(id, batch_id, seq, machine_id, iface, check_name, block24, targets, "
                           "params, status, queued_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
        for r in rows:
            await self.emit_job(r[0])
        self.kick(mid)
        return {"batch_id": batch, "jobs": [r[0] for r in rows], "estimate_s": estimate(plan, params)}

    # ---------- workers ----------
    def kick(self, mid: int):
        t = self.workers.get(mid)
        if t is None or t.done():
            self.workers[mid] = asyncio.create_task(self._worker(mid))

    async def _next(self, mid):
        return await self.db.one("SELECT * FROM jobs WHERE machine_id=? AND status='queued' "
                                 "ORDER BY batch_id, seq LIMIT 1", (mid,))

    async def _worker(self, mid: int):
        while True:
            job = await self._next(mid)
            if not job:
                self.workers.pop(mid, None)
                if await self._next(mid):  # closes the race with kick() during the last query
                    self.kick(mid)
                return
            await self._run(job)

    async def _ctx(self, job: dict, m: dict) -> dict:
        names = {r["name"] for r in await self.db.all("SELECT name FROM interfaces WHERE machine_id=?", (m["id"],))}
        ctx = {**loads(job["params"], {}), "iface": job["iface"], "targets": loads(job["targets"], []),
               "job_id": job["id"], "known_ifaces": names, "privileged": m["mode"] == "cap"}
        if job["check_name"] == "services":
            prior: dict[str, dict] = {}
            for r in await self.db.all(
                    "SELECT f.host_ip, f.protocol, f.port FROM findings f JOIN jobs j ON j.id=f.job_id "
                    "WHERE j.batch_id=? AND f.iface=? AND f.block24=? AND f.check_name IN ('syn','udp') "
                    "AND f.evidence='strong' AND f.port IS NOT NULL", (job["batch_id"], job["iface"], job["block24"])):
                prior.setdefault(r["host_ip"], {"tcp": [], "udp": []})[r["protocol"]].append(r["port"])
            ctx["prior_open"] = prior
        return ctx

    async def _run(self, job: dict):
        jid, mid = job["id"], job["machine_id"]
        live = self.live[jid] = {"pgid": None, "kill": False, "task": None, "machine_id": mid}
        try:
            m = await self.ssh.machine(mid)
            if not m["mode"]:
                raise RuntimeError("machine not ready: run connect / prerequisite check")
            ctx = await self._ctx(job, m)
            argv = REGISTRY[job["check_name"]].build(ctx)
            if argv is None:
                await self._finish(jid, "done", error="skipped: no strong open ports from earlier phases")
                return
            sudo = await self.ssh.sudo_input(mid)
            scope = await self.scope()
            src = await self.db.one("SELECT ipv4 FROM interfaces WHERE machine_id=? AND name=?", (mid, job["iface"]))
            await self.db.run(
                "UPDATE jobs SET status='running', argv=?, command=?, started_at=?, source_ip=?, source_zone=?, "
                "target_tag=? WHERE id=?",
                (dumps(argv), shlex.join(argv), now(), src and src["ipv4"],
                 (await self.iface_zones(mid, scope)).get(job["iface"]),
                 tg.block_tags(scope).get(ip.IPv4Network(job["block24"]), "unscoped"), jid))
            await self.emit_job(jid)
            rc = await self._stream(jid, mid, cmd.wrap_scan(argv, m["mode"]), sudo, live, argv)

            rows, flags, error = [], [], None
            if not live["kill"]:
                rc_cat, xml, err = await self.ssh.run(mid, cmd.cat_cmd(jid, m["mode"]), stdin=sudo, job_id=jid)
                if rc_cat == 0 and xml.strip():
                    try:
                        rows, flags = process(job["check_name"], xml, ctx)
                    except ET.ParseError as e:
                        error = f"XML parse error: {e}"
                else:
                    error = f"could not read remote XML: {err.strip()[:200]}"
            await self.ssh.run(mid, cmd.rm_cmd(jid, m["mode"]), stdin=sudo, job_id=jid)
            if rows:
                ts = now()
                await self.db.many(
                    "INSERT INTO findings(job_id, machine_id, iface, host_ip, block24, check_name, protocol, port, state, "
                    "reason, reason_ip, ttl, service, evidence, detail, seen_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    [(jid, mid, job["iface"], r["host_ip"], block_of(r["host_ip"]), job["check_name"], r["protocol"],
                      r["port"], r["state"], r["reason"], r["reason_ip"], r["ttl"], r["service"], r["evidence"],
                      dumps(r["detail"]), ts) for r in rows])
            status = "killed" if live["kill"] else ("done" if rc == 0 and not error else "failed")
            await self._finish(jid, status, rc, flags, error)
            await self.hub.send({"type": "graph", "machine_id": mid, "iface": job["iface"], "block24": job["block24"]})
        except asyncio.CancelledError:
            if not live["kill"]:
                raise
            await self._finish(jid, "killed", error="killed (channel closed)")
        except Exception as e:
            await self._finish(jid, "killed" if live["kill"] else "failed", error=f"{type(e).__name__}: {e}")
        finally:
            self.live.pop(jid, None)

    async def _stream(self, jid, mid, command, sudo, live, argv) -> int:
        log = open(self.log_dir / f"{jid}.log", "a", encoding="utf-8")
        log.write(f"$ {shlex.join(argv)}\n")
        buf = ""

        async def on_data(data: str):
            nonlocal buf
            if live["pgid"] is None:
                buf += data
                m = PGID_RE.search(buf)
                if m:
                    live["pgid"] = int(m[1])
                    await self.db.run("UPDATE jobs SET pgid=? WHERE id=?", (live["pgid"], jid))
                    data, buf = buf.replace(m[0], ""), ""
                elif len(buf) < 4096:
                    return
                else:
                    data, buf = buf, ""
            if data:
                log.write(data)
                log.flush()
                await self.hub.send({"type": "output", "job": jid, "data": data})

        try:
            live["task"] = asyncio.create_task(self.ssh.stream(mid, command, sudo, on_data, job_id=jid))
            try:
                return await live["task"]
            except asyncio.CancelledError:
                if live["kill"] and live["task"].cancelled():
                    return -1
                raise
        finally:
            log.close()

    async def _finish(self, jid, status, rc=None, flags=None, error=None):
        await self.db.run("UPDATE jobs SET status=?, exit_code=?, flags=?, error=?, finished_at=? WHERE id=?",
                          (status, rc, dumps(flags or []), error, now(), jid))
        await self.emit_job(jid)

    async def emit_job(self, jid):
        await self.hub.send({"type": "job", "job": await self.job(jid)})

    async def job(self, jid) -> dict | None:
        j = await self.db.one("SELECT id, batch_id, seq, machine_id, iface, check_name, block24, targets, argv, command, "
                              "status, pgid, exit_code, queued_at, started_at, finished_at, flags, error FROM jobs "
                              "WHERE id=?", (jid,))
        if j:
            j["targets"], j["argv"], j["flags"] = loads(j["targets"], []), loads(j["argv"]), loads(j["flags"], [])
        return j

    # ---------- kill ----------
    async def _signal(self, mid, pgid):
        """TERM the process group, wait, KILL if it is still there. Separate SSH exec each time."""
        m = await self.ssh.machine(mid)
        sudo = await self.ssh.sudo_input(mid)
        await self.ssh.run(mid, cmd.kill_cmd(pgid, "TERM", m["mode"]), stdin=sudo, timeout=20)
        await asyncio.sleep(self.grace)
        rc, _, _ = await self.ssh.run(mid, cmd.kill_cmd(pgid, "0", m["mode"]), stdin=sudo, timeout=20)
        if rc == 0:
            await self.ssh.run(mid, cmd.kill_cmd(pgid, "KILL", m["mode"]), stdin=sudo, timeout=20)
        return rc != 0

    async def _terminate(self, live: dict):
        live["kill"] = True
        for _ in range(50):  # PGID arrives with the first output line
            if live["pgid"] or (live["task"] and live["task"].done()):
                break
            await asyncio.sleep(0.1)
        if live["pgid"]:
            try:
                await self._signal(live["machine_id"], live["pgid"])
            except Exception:
                pass  # fall through to closing the channel
        t = live["task"]
        if t and not t.done():
            try:
                await asyncio.wait_for(asyncio.shield(t), 5)
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                t.cancel()

    async def kill(self, jid: str):
        j = await self.db.one("SELECT status FROM jobs WHERE id=?", (jid,))
        if not j:
            raise KeyError(jid)
        if j["status"] == "queued":
            await self._finish(jid, "killed", error="cancelled before start")
        elif jid in self.live:
            await self._terminate(self.live[jid])
        elif j["status"] == "running":
            await self.reconcile([jid])

    async def master_kill(self):
        queued = await self.db.all("SELECT id FROM jobs WHERE status='queued'")
        await self.db.run("UPDATE jobs SET status='killed', error='cancelled (master kill)', finished_at=? "
                          "WHERE status='queued'", (now(),))
        for j in queued:
            await self.emit_job(j["id"])
        await asyncio.gather(*(self._terminate(l) for l in list(self.live.values())), return_exceptions=True)
        return {"cancelled": len(queued)}

    # ---------- restart reconciliation ----------
    async def reconcile(self, only: list[str] | None = None):
        rows = await self.db.all("SELECT * FROM jobs WHERE status='running'")
        for j in rows:
            if only and j["id"] not in only:
                continue
            try:
                m = await self.ssh.machine(j["machine_id"])
                if j["pgid"] and m["mode"]:
                    sudo = await self.ssh.sudo_input(j["machine_id"])
                    rc, _, _ = await self.ssh.run(j["machine_id"], cmd.kill_cmd(j["pgid"], "0", m["mode"]), stdin=sudo)
                    if rc == 0:
                        await self._signal(j["machine_id"], j["pgid"])
                        status, err = "killed", f"process group {j['pgid']} still alive after backend restart: killed"
                    else:
                        status, err = "failed", "backend restarted while running; remote process gone"
                    try:
                        await self.ssh.run(j["machine_id"], cmd.rm_cmd(j["id"], m["mode"]), stdin=sudo, job_id=j["id"])
                    except Exception:
                        pass  # leftover /tmp file is harmless; status matters more
                else:
                    status, err = "failed", "backend restarted before the remote process reported its PGID"
            except Exception as e:
                status, err = "failed", f"backend restarted; could not verify remote process (pgid {j['pgid']}): {e}"
            await self._finish(j["id"], status, error=err)
        if only is None:
            # never auto-launch scans after a restart
            await self.db.run("UPDATE jobs SET status='killed', error='cancelled: backend restarted', finished_at=? "
                              "WHERE status='queued'", (now(),))


def estimate(plan, params) -> float:
    per = PER_PROBE[params["timing"]]
    total = 0.0
    for _, c, _, targets in plan:
        hosts = sum(ip.IPv4Network(t).num_addresses for t in targets)
        ports = {"syn": len(cmd.expand_ports(params["tcp_ports"])), "udp": 10 * len(cmd.expand_ports(params["udp_ports"])),
                 "icmp": 2, "services": 5, "egress": len(cmd.expand_ports(params["egress_ports"]))}[c]
        total += hosts * ports * per
    return round(total)
