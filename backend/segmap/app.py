"""FastAPI app: REST + one WebSocket (/ws) for job status, output and graph updates."""
import asyncio
import csv
import io
import ipaddress as ip
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime
from urllib.parse import urlparse

import asyncssh
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from . import commands as cmd
from . import config
from . import targets as tg
from .checks import REGISTRY
from .crypto import Vault, load_key
from .db import DB, dumps, loads
from .jobs import DEFAULT_PROFILE, Hub, JobManager
from .ssh import HostKeyError, SSHManager, fingerprint, probe

# Severity of reaching <target tag> from an interface in <source zone>. One place; a flow matrix replaces it later.
SEVERITY = {
    ("out-of-scope", "CDE"): "critical", ("non-CDE", "CDE"): "critical", ("wireless", "CDE"): "critical",
    ("CDE", "out-of-scope"): "critical", (None, "CDE"): "high", ("out-of-scope", "connected-to"): "high",
    ("wireless", "connected-to"): "high",
}
ALLOWED_HOSTS = {"127.0.0.1", "localhost", config.HOST} | set(filter(None, os.environ.get("SEGMAP_ALLOWED_HOSTS", "").split(",")))
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})$")
TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,31}$")


class S:  # app singletons
    db: DB
    ssh: SSHManager
    jobs: JobManager
    hub: Hub


@asynccontextmanager
async def lifespan(app):
    config.DATA.mkdir(parents=True, exist_ok=True)
    os.chmod(config.DATA, 0o700)
    S.db = DB(config.DATA / "segmap.db")
    await S.db.open()
    S.ssh = SSHManager(S.db, Vault(load_key(config.DATA)))
    S.hub = Hub()
    S.jobs = JobManager(S.db, S.ssh, S.hub, config.DATA / "logs", config.KILL_GRACE)
    reconcile = asyncio.create_task(S.jobs.reconcile())
    yield
    reconcile.cancel()
    try:
        await asyncio.wait_for(S.jobs.master_kill(), 30)  # never leave scans running behind us
    except Exception:
        pass
    await S.db.close()


app = FastAPI(title="SegMap", lifespan=lifespan)


def _host_ok(h: str | None) -> bool:
    if not h:
        return False
    return (urlparse("//" + h).hostname or "") in ALLOWED_HOSTS


@app.middleware("http")
async def guard(request: Request, call_next):
    """DNS-rebinding / CSRF guard: only localhost Host, and same-origin for state-changing calls."""
    if not _host_ok(request.headers.get("host")):
        return PlainTextResponse("forbidden host", 403)
    origin = request.headers.get("origin")
    if request.method not in ("GET", "HEAD") and origin and (urlparse(origin).hostname or "") not in ALLOWED_HOSTS:
        return PlainTextResponse("forbidden origin", 403)
    return await call_next(request)


@app.exception_handler(ValueError)
async def _value_error(_, e):
    return JSONResponse({"detail": str(e)}, 400)


@app.exception_handler(KeyError)
async def _key_error(_, e):
    return JSONResponse({"detail": f"not found: {e}"}, 404)


@app.exception_handler(HostKeyError)
async def _hk_error(_, e):
    return JSONResponse({"detail": str(e)}, 409)


@app.exception_handler(asyncssh.Error)
async def _ssh_error(_, e):
    return JSONResponse({"detail": f"SSH error: {e}"}, 502)


@app.exception_handler(OSError)
async def _os_error(_, e):
    return JSONResponse({"detail": f"connection error: {e}"}, 502)


# ---------- models ----------
class MachineIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    host: str
    port: int = Field(22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=64)
    password: str = ""
    key: str = ""
    passphrase: str = ""
    sudo_password: str = ""

    @field_validator("host")
    @classmethod
    def _host(cls, v):
        if not HOST_RE.match(v):
            raise ValueError("invalid host")
        return v


class TrustIn(BaseModel):
    fingerprint: str


class IfacePatch(BaseModel):
    hidden: bool | None = None
    zone_override: str | None = None


class ScopeIn(BaseModel):
    text: str = Field(max_length=1_000_000)
    tag: str
    note: str = ""


class TagIn(BaseModel):
    name: str
    color: str = Field(pattern=r"^#[0-9a-fA-F]{6}$")


class JobsIn(BaseModel):
    machine_id: int
    type: str = Field("single", pattern=r"^(single|interface|machine)$")
    ifaces: list[str] | None = None
    blocks: list[str] | None = None
    checks: list[str] | None = None
    dry_run: bool = False


# ---------- helpers ----------
async def machine_out(mid: int) -> dict:
    m = await S.ssh.machine(mid)
    zones = await S.jobs.iface_zones(mid)
    ifaces = await S.db.all("SELECT id, name, ipv4, mac, state, hidden, zone_override FROM interfaces "
                            "WHERE machine_id=? ORDER BY name", (mid,))
    for i in ifaces:
        i["zone"] = zones.get(i["name"])
        i["hidden"] = bool(i["hidden"])
    sec = S.ssh.vault.open(m["secret"])
    return {
        "id": m["id"], "name": m["name"], "host": m["host"], "port": m["port"], "username": m["username"],
        "auth": "key" if sec.get("key") else "password", "has_sudo_password": bool(sec.get("sudo_password")),
        "status": m["status"], "error": m["error"], "mode": m["mode"],
        "host_key_fp": fingerprint(m["host_key"]), "pending_fp": fingerprint(m["pending_key"]),
        "prereq": loads(m["prereq"]), "facts": loads(m["facts"]), "connected": mid in S.ssh.conns,
        "interfaces": ifaces,
    }


async def tags() -> dict[str, dict]:
    return {t["name"]: t for t in await S.db.all("SELECT * FROM tags ORDER BY rank, name")}


# ---------- state ----------
@app.get("/api/state")
async def state():
    machines = [await machine_out(r["id"]) for r in await S.db.all("SELECT id FROM machines ORDER BY id")]
    return {
        "tags": list((await tags()).values()),
        "scope": await S.db.all("SELECT * FROM scope ORDER BY tag, cidr"),
        "machines": machines,
        "profile": await S.jobs.profile(),
        "checks": [{"name": c.name, "label": c.label, "reqs": c.reqs, "per_block": c.per_block} for c in REGISTRY.values()],
        "jobs": [await S.jobs.job(j["id"]) for j in await S.db.all(
            "SELECT id FROM jobs ORDER BY batch_id DESC, seq DESC LIMIT 500")],
    }


# ---------- machines ----------
@app.post("/api/machines")
async def add_machine(m: MachineIn):
    if not m.password and not m.key:
        raise ValueError("password or private key required")
    if m.key:
        asyncssh.import_private_key(m.key, m.passphrase or None)  # validate now, fail early
    secret = S.ssh.vault.seal({"password": m.password, "key": m.key, "passphrase": m.passphrase,
                               "sudo_password": m.sudo_password})
    mid = await S.db.run("INSERT INTO machines(name, host, port, username, secret) VALUES (?,?,?,?,?)",
                         (m.name, m.host, m.port, m.username, secret))
    return await machine_out(mid)


@app.delete("/api/machines/{mid}")
async def del_machine(mid: int):
    if any(l["machine_id"] == mid for l in S.jobs.live.values()):
        raise ValueError("machine has running jobs; kill them first")
    await S.ssh.disconnect(mid)
    await S.db.run("DELETE FROM machines WHERE id=?", (mid,))
    return {"ok": True}


@app.post("/api/machines/{mid}/hostkey")
async def host_key(mid: int):
    return await S.ssh.fetch_host_key(mid)


@app.post("/api/machines/{mid}/trust")
async def trust(mid: int, t: TrustIn):
    await S.ssh.trust(mid, t.fingerprint)
    return await machine_out(mid)


@app.post("/api/machines/{mid}/connect")
async def connect(mid: int):
    m = await S.ssh.machine(mid)
    if not m["host_key"] or m["status"] == "hostkey_changed":
        return {"needs_trust": True, **(await S.ssh.fetch_host_key(mid))}
    try:
        await S.ssh.connect(mid)
    except HostKeyError:
        return {"needs_trust": True, **(await S.ssh.fetch_host_key(mid))}
    except (asyncssh.Error, OSError) as e:
        await S.db.run("UPDATE machines SET status='error', error=? WHERE id=?", (f"connect failed: {e}", mid))
        raise
    await probe(S.ssh, mid)
    return await machine_out(mid)


@app.post("/api/machines/{mid}/disconnect")
async def disconnect(mid: int):
    await S.ssh.disconnect(mid)
    return await machine_out(mid)


@app.patch("/api/interfaces/{iid}")
async def patch_iface(iid: int, p: IfacePatch):
    if p.hidden is not None:
        await S.db.run("UPDATE interfaces SET hidden=? WHERE id=?", (int(p.hidden), iid))
    if p.zone_override is not None:
        z = p.zone_override or None
        if z and z not in await tags():
            raise ValueError(f"unknown tag {z!r}")
        await S.db.run("UPDATE interfaces SET zone_override=? WHERE id=?", (z, iid))
    return {"ok": True}


# ---------- scope & tags ----------
@app.post("/api/scope")
async def add_scope(s: ScopeIn):
    if s.tag not in await tags():
        raise ValueError(f"unknown tag {s.tag!r}")
    nets = tg.parse_targets(s.text)
    if not nets:
        raise ValueError("no targets")
    existing = await S.jobs.scope()
    tg.block_tags(existing + [(n, s.tag) for n in nets])  # rejects two tags in one /24
    await S.db.many("INSERT OR IGNORE INTO scope(cidr, tag, note) VALUES (?,?,?)",
                    [(str(n), s.tag, s.note[:200]) for n in nets])
    return {"added": len(nets)}


@app.delete("/api/scope/{sid}")
async def del_scope(sid: int):
    await S.db.run("DELETE FROM scope WHERE id=?", (sid,))
    return {"ok": True}


@app.post("/api/tags")
async def add_tag(t: TagIn):
    if not TAG_RE.match(t.name):
        raise ValueError("invalid tag name")
    await S.db.run("INSERT INTO tags(name, color) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET color=excluded.color",
                   (t.name, t.color))
    return {"ok": True}


@app.delete("/api/tags/{name}")
async def del_tag(name: str):
    t = (await tags()).get(name)
    if not t or t["builtin"]:
        raise ValueError("built-in or unknown tag")
    if await S.db.one("SELECT 1 FROM scope WHERE tag=?", (name,)):
        raise ValueError("tag in use by scope entries")
    await S.db.run("DELETE FROM tags WHERE name=?", (name,))
    return {"ok": True}


# ---------- profile ----------
@app.get("/api/profile")
async def get_profile():
    return await S.jobs.profile()


@app.put("/api/profile")
async def put_profile(p: dict):
    prof = {k: p[k] for k in DEFAULT_PROFILE if k in p}
    merged = {**DEFAULT_PROFILE, **prof}
    # validate with the command builder so bad values never get stored
    cmd.check_timing(merged["timing"])
    cmd.parse_ports(merged["tcp_ports"])
    cmd.parse_ports(merged["udp_ports"])
    cmd.parse_ports(merged["egress_ports"])
    cmd._advanced({k: v for k, v in (merged["advanced"] or {}).items() if v not in (None, "")})
    if merged["egress_listener"]:
        cmd.check_ip(merged["egress_listener"])
    if not re.fullmatch(r"[A-Za-z0-9_-]{0,64}", merged["egress_token"] or ""):
        raise ValueError("egress token: letters, digits, _ and - only")
    for c in merged["checks"]:
        if c not in REGISTRY:
            raise ValueError(f"unknown check {c!r}")
    await S.db.kv_set("profile", prof)
    return merged


# ---------- jobs ----------
@app.post("/api/jobs")
async def enqueue(j: JobsIn):
    return await S.jobs.enqueue(j.model_dump())


@app.post("/api/jobs/{jid}/kill")
async def kill(jid: str):
    asyncio.create_task(S.jobs.kill(jid))
    return {"ok": True}


@app.post("/api/kill-all")
async def kill_all():
    return await S.jobs.master_kill()


@app.get("/api/jobs/{jid}/log", response_class=PlainTextResponse)
async def job_log(jid: str):
    cmd.check_job(jid)
    p = config.DATA / "logs" / f"{jid}.log"
    return p.read_text(errors="replace") if p.exists() else ""


# ---------- graph & findings ----------
@app.get("/api/graph")
async def graph():
    tag_rows = await tags()
    scope = await S.jobs.scope()
    bmap = tg.block_tags(scope)
    machines = []
    zones = {}
    for r in await S.db.all("SELECT id, name, host, status FROM machines ORDER BY id"):
        z = await S.jobs.iface_zones(r["id"], scope)
        zones[r["id"]] = z
        ifs = await S.db.all("SELECT name, ipv4, hidden FROM interfaces WHERE machine_id=? ORDER BY name", (r["id"],))
        machines.append({**r, "interfaces": [{"name": i["name"], "ipv4": i["ipv4"], "zone": z.get(i["name"])}
                                             for i in ifs if not i["hidden"]]})
    blocks: dict[str, dict] = {str(b): {"cidr": str(b), "tag": t, "flags": [], "scanned": False}
                               for b, t in sorted(bmap.items())}
    for j in await S.db.all("SELECT machine_id, iface, block24, flags, status FROM jobs WHERE block24 IS NOT NULL"):
        b = blocks.get(j["block24"])
        if b is None:
            continue
        b["scanned"] = b["scanned"] or j["status"] == "done"
        for f in loads(j["flags"], []):
            f = {**f, "machine_id": j["machine_id"], "iface": j["iface"]}
            if f not in b["flags"]:
                b["flags"].append(f)
    edges = []
    for e in await S.db.all(
            "SELECT machine_id, iface, block24, "
            "COUNT(DISTINCT CASE WHEN evidence='strong' THEN host_ip END) AS strong_hosts, "
            "COUNT(DISTINCT CASE WHEN evidence='weak' THEN host_ip END) AS weak_hosts, "
            "COUNT(DISTINCT CASE WHEN evidence='strong' AND port IS NOT NULL THEN protocol||'/'||port END) AS strong_ports, "
            "SUM(COALESCE(json_array_length(detail, '$.issues'), 0)) AS issues "
            "FROM findings GROUP BY machine_id, iface, block24"):
        if e["block24"] not in blocks:
            blocks[e["block24"]] = {"cidr": e["block24"], "tag": "unscoped", "flags": [], "scanned": True}
        src = zones.get(e["machine_id"], {}).get(e["iface"])
        e["source_zone"] = src
        e["severity"] = SEVERITY.get((src, blocks[e["block24"]]["tag"]), "info") if e["strong_hosts"] else "none"
        e["id"] = f"{e['machine_id']}|{e['iface']}|{e['block24']}"
        edges.append(e)
    return {"tags": list(tag_rows.values()), "machines": machines, "blocks": list(blocks.values()), "edges": edges}


@app.get("/api/findings")
async def findings(machine_id: int, iface: str, block24: str):
    rows = await S.db.all(
        "SELECT f.*, j.started_at AS job_started, j.finished_at AS job_finished, j.command AS job_command "
        "FROM findings f JOIN jobs j ON j.id=f.job_id WHERE f.machine_id=? AND f.iface=? AND f.block24=? "
        "ORDER BY f.evidence DESC, f.host_ip, f.protocol, f.port", (machine_id, iface, block24))
    for r in rows:
        r["detail"] = loads(r["detail"], {})
    flags = []
    for j in await S.db.all("SELECT flags FROM jobs WHERE machine_id=? AND iface=? AND block24=?",
                            (machine_id, iface, block24)):
        flags += [f for f in loads(j["flags"], []) if f not in flags]
    return {"findings": rows, "flags": flags}


@app.delete("/api/findings")
async def clear_findings(machine_id: int | None = None, iface: str | None = None, block24: str | None = None):
    """No params: clear everything. With machine_id+iface+block24: clear one graph edge. Audit log untouched."""
    if machine_id is None:
        await S.db.run("DELETE FROM findings")
        await S.db.run("UPDATE jobs SET flags=NULL")
    else:
        if not iface or not block24:
            raise ValueError("machine_id, iface and block24 are required together")
        edge = (machine_id, iface, block24)
        await S.db.run("DELETE FROM findings WHERE machine_id=? AND iface=? AND block24=?", edge)
        await S.db.run("UPDATE jobs SET flags=NULL WHERE machine_id=? AND iface=? AND block24=?", edge)
    await S.hub.send({"type": "graph"})
    return {"ok": True}


@app.delete("/api/blocks")
async def del_block(cidr: str):
    """Delete a /24 from the graph: its scope entries and findings. Audit log untouched."""
    b = ip.IPv4Network(cidr)
    if b.prefixlen != 24:
        raise ValueError("block must be a /24")
    ids = []
    for r in await S.db.all("SELECT id, cidr FROM scope"):
        n = ip.IPv4Network(r["cidr"])
        if n.subnet_of(b):
            ids.append(r["id"])
        elif n.overlaps(b):
            raise ValueError(f"{b} is part of scope entry {n}; edit that entry in the sidebar")
    await S.db.many("DELETE FROM scope WHERE id=?", [(i,) for i in ids])
    await S.db.run("DELETE FROM findings WHERE block24=?", (str(b),))
    await S.db.run("UPDATE jobs SET flags=NULL WHERE block24=?", (str(b),))
    await S.hub.send({"type": "graph"})
    return {"scope_deleted": len(ids)}


# ---------- positions ----------
@app.get("/api/positions")
async def get_positions():
    return await S.db.kv_get("positions", {})


@app.put("/api/positions")
async def put_positions(p: dict):
    clean = {str(k)[:200]: {"x": float(v["x"]), "y": float(v["y"])} for k, v in p.items()}
    await S.db.kv_set("positions", clean)
    return {"ok": True}


# display-only graph edits: renamed labels and hidden node/edge ids (hidden = not rendered, not exported)
@app.get("/api/graph-view")
async def get_graph_view():
    return await S.db.kv_get("graph_view", {"labels": {}, "hidden": []})


@app.put("/api/graph-view")
async def put_graph_view(v: dict):
    clean = {"labels": {str(k)[:200]: str(t).strip()[:100] for k, t in (v.get("labels") or {}).items() if str(t).strip()},
             "hidden": sorted({str(x)[:200] for x in v.get("hidden") or []})}
    await S.db.kv_set("graph_view", clean)
    return clean


# ---------- exports ----------
def _csv(rows: list[dict], name: str) -> Response:
    buf = io.StringIO()
    if rows:
        w = csv.DictWriter(buf, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


async def _export_rows():
    scope = await S.jobs.scope()
    bmap = {str(k): v for k, v in tg.block_tags(scope).items()}
    zones: dict[int, dict] = {}
    rows = await S.db.all(
        "SELECT f.seen_at, m.name AS machine, m.host AS machine_host, f.machine_id, f.iface, i.ipv4 AS iface_ip, "
        "f.block24, f.host_ip, f.check_name, f.protocol, f.port, f.state, f.reason, f.reason_ip, f.ttl, f.service, "
        "f.evidence, f.detail, f.job_id FROM findings f JOIN machines m ON m.id=f.machine_id "
        "LEFT JOIN interfaces i ON i.machine_id=f.machine_id AND i.name=f.iface ORDER BY f.machine_id, f.iface, f.block24, "
        "f.host_ip, f.port")
    for r in rows:
        if r["machine_id"] not in zones:
            zones[r["machine_id"]] = await S.jobs.iface_zones(r["machine_id"], scope)
        r["source_zone"] = zones[r["machine_id"]].get(r["iface"])
        r["target_tag"] = bmap.get(r["block24"], "unscoped")
        r["severity"] = SEVERITY.get((r["source_zone"], r["target_tag"]), "info") if r["evidence"] == "strong" else ""
    return rows


@app.get("/api/export/findings.json")
async def export_json():
    rows = await _export_rows()
    for r in rows:
        r["detail"] = loads(r["detail"], {})
    return JSONResponse(rows, headers={"Content-Disposition": 'attachment; filename="segmap-findings.json"'})


@app.get("/api/export/findings.csv")
async def export_csv():
    return _csv(await _export_rows(), "segmap-findings.csv")


def _local(ts: str | None) -> str:
    """UTC ISO string from the DB -> backend host's local time with offset."""
    return datetime.fromisoformat(ts).astimezone().isoformat(timespec="seconds") if ts else ""


async def _add_scope_cols(rows: list[dict], time_cols: tuple[str, ...]) -> list[dict]:
    """Add *_local times. Zone/tag/IP come from the run-time snapshot; rows written before snapshots
    existed fall back to current scope and say so in snapshot_source."""
    scope, zones = None, {}
    for r in rows:
        for c in time_cols:
            r[f"{c}_local"] = _local(r[c])
        mid = r.pop("machine_id")
        legacy_ip = r.pop("legacy_source_ip")
        if r["target_tag"] is not None:
            r["snapshot_source"] = "run-time"
        elif r["block24"]:  # scan row from before snapshots: best effort, current state
            if scope is None:
                scope = await S.jobs.scope()
                bmap = {str(k): v for k, v in tg.block_tags(scope).items()}
            if mid is not None and mid not in zones:
                zones[mid] = await S.jobs.iface_zones(mid, scope)
            r["source_ip"] = legacy_ip
            r["source_zone"] = zones.get(mid, {}).get(r["iface"])
            r["target_tag"] = bmap.get(r["block24"], "unscoped")
            r["snapshot_source"] = "export-time (pre-snapshot row)"
        else:
            r["snapshot_source"] = ""  # helper command not tied to a job
    return rows


@app.get("/api/export/timeline.csv")
async def export_timeline():
    """PCI DSS 11.5.1 support: exact scan timeline so the SOC can match IDS/IPS alerts."""
    rows = await S.db.all(
        "SELECT j.started_at, j.finished_at, j.machine_id, m.name AS machine, m.host AS machine_host, j.iface, "
        "j.source_ip, i.ipv4 AS legacy_source_ip, j.source_zone, j.check_name, j.block24, j.target_tag, j.targets, "
        "j.command, j.status, j.exit_code, j.error, j.id AS job_id FROM jobs j "
        "JOIN machines m ON m.id=j.machine_id LEFT JOIN interfaces i ON i.machine_id=j.machine_id AND i.name=j.iface "
        "WHERE j.started_at IS NOT NULL ORDER BY j.started_at")
    return _csv(await _add_scope_cols(rows, ("started_at", "finished_at")), "segmap-scan-timeline.csv")


@app.get("/api/export/audit.csv")
async def export_audit():
    """Every remote command executed (scans plus helper cat/rm/kill/probe), with from/to context as of run time."""
    rows = await S.db.all(
        "SELECT a.id, a.ts, a.actor, a.machine_id, COALESCE(a.machine_name, m.name) AS machine, "
        "a.target_host AS machine_host, COALESCE(a.iface, j.iface) AS iface, a.source_ip, i.ipv4 AS legacy_source_ip, "
        "a.source_zone, COALESCE(a.check_name, j.check_name) AS check_name, COALESCE(a.block24, j.block24) AS block24, "
        "a.target_tag, COALESCE(a.targets, j.targets) AS targets, j.status AS job_status, j.exit_code, "
        "a.job_id, a.command FROM audit a LEFT JOIN machines m ON m.id=a.machine_id "
        "LEFT JOIN jobs j ON j.id=a.job_id LEFT JOIN interfaces i ON i.machine_id=j.machine_id AND i.name=j.iface "
        "ORDER BY a.id")
    return _csv(await _add_scope_cols(rows, ("ts",)), "segmap-audit.csv")


# ---------- websocket ----------
@app.websocket("/ws")
async def ws(sock: WebSocket):
    origin = sock.headers.get("origin")
    if not _host_ok(sock.headers.get("host")) or (origin and (urlparse(origin).hostname or "") not in ALLOWED_HOSTS):
        await sock.close(code=1008)
        return
    await sock.accept()
    S.hub.clients.add(sock)
    try:
        while True:
            await sock.receive_text()  # client sends nothing meaningful; keeps the socket open
    except WebSocketDisconnect:
        pass
    finally:
        S.hub.clients.discard(sock)


if config.FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=config.FRONTEND_DIST, html=True), name="ui")
