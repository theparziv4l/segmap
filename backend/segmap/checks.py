"""Pluggable checks. One check = argv builder + post-classifier + render hint.
Parsing (nmapxml) and generic evidence (evidence.classify/analyze) are shared.

Adding a check: write build(ctx) -> argv | None and optionally post(scan, rows, ctx), register it."""
import re
from dataclasses import dataclass
from typing import Callable

from . import commands as cmd
from . import evidence, nmapxml


@dataclass(frozen=True)
class Check:
    name: str
    label: str
    reqs: str                       # PCI DSS v4.0.1 requirements this evidences
    build: Callable[[dict], list[str] | None]   # None = nothing to do, job is skipped
    post: Callable[[dict, list, dict], None] | None = None
    heuristics: bool = True         # run /24 middlebox heuristics
    per_block: bool = True          # False = runs once per interface (egress)


def _kw(ctx):
    return {"known_ifaces": ctx["known_ifaces"], "privileged": ctx.get("privileged", False),
            "advanced": ctx.get("advanced")}


# ---------- egress ----------
def _egress_post(scan, rows, ctx):
    token = ctx.get("egress_token") or ""
    for r in rows:
        if r["evidence"] != "strong":
            continue
        banner = r["detail"].get("scripts", {}).get("banner", "")
        if token and token in banner:
            r["detail"]["token"] = True
        else:
            r["evidence"] = "weak"
            r["detail"]["unverified"] = "SYN-ACK without listener token (possible proxy or other service)"


# ---------- services ----------
WEAK_SSH = re.compile(r"diffie-hellman-group1-sha1|diffie-hellman-group-exchange-sha1|arcfour|3des-cbc|"
                      r"blowfish-cbc|hmac-md5|ssh-dss")


def service_issues(r: dict, hostscripts: dict) -> list[dict]:
    s = (r["service"] or "").lower()
    d = r["detail"]
    sc = d.get("scripts", {})
    ssl = d.get("tunnel") == "ssl"
    prod = " ".join(filter(None, (d.get("product"), d.get("version"), d.get("extrainfo"))))
    out = []

    def add(issue, req):
        out.append({"issue": issue, "req": req})

    if s == "telnet":
        add("Telnet: cleartext admin/auth", "2.2.4, 2.2.7, 8.3.2")
    if s == "ftp" and not ssl:
        add("FTP: cleartext credentials", "2.2.5, 8.3.2")
    if "Anonymous FTP login allowed" in sc.get("ftp-anon", ""):
        add("Anonymous FTP login allowed", "2.2.2, 2.2.4")
    if s in ("login", "shell", "exec"):
        add("r-service (rlogin/rsh/rexec): cleartext", "2.2.4, 2.2.7, 8.3.2")
    if s == "tftp":
        add("TFTP: unauthenticated file transfer", "2.2.4")
    if s == "http" and not ssl:
        title = sc.get("http-title", "").strip()
        add("HTTP without TLS" + (f" ({title})" if title else "") + " - verify if admin/login", "2.2.7, 8.3.2")
    if s == "ldap" and not ssl:
        add("LDAP without TLS (cleartext simple bind possible)", "8.3.2")
    if s == "snmp" and re.search(r"v1|v2c|public", prod, re.I):
        add("SNMP v1/v2c (community string, cleartext)", "2.2.5, 2.2.7, 2.3.1")
    if s == "vnc":
        vi = sc.get("vnc-info", "")
        if re.search(r"None \(1\)", vi):
            add("VNC without authentication", "2.2.2, 8.3.1")
        if not re.search(r"VeNCrypt|TLS", vi):
            add("VNC without TLS", "2.2.7")
    if "access is granted" in sc.get("x11-access", ""):
        add("X11 server open to network", "2.2.4")
    if sc.get("nfs-showmount", "").strip():
        add("NFS exports visible", "2.2.4")
    if s == "redis" and "Version" in sc.get("redis-info", ""):
        add("Redis without authentication", "2.2.4, 8.3.1")
    if s == "mongodb" and sc.get("mongodb-info") and "unauthorized" not in sc["mongodb-info"].lower():
        add("MongoDB without authentication", "2.2.4, 8.3.1")
    if r["port"] in (139, 445) and "SMBv1" in hostscripts.get("smb-protocols", ""):
        add("SMBv1 enabled", "2.2.5")
    if WEAK_SSH.search(sc.get("ssh2-enum-algos", "")):
        add("weak SSH algorithms offered", "2.2.7")
    if "Native RDP: SUCCESS" in sc.get("rdp-enum-encryption", ""):
        add("RDP native (non-TLS) security layer accepted", "2.2.7")
    return out


def _services_post(scan, rows, ctx):
    hs = {h["ip"]: h["hostscripts"] for h in scan["hosts"]}
    for r in rows:
        if r["evidence"] == "strong" and r["port"] is not None:
            r["detail"]["issues"] = service_issues(r, hs.get(r["host_ip"], {}))


def _services_build(ctx):
    prior = ctx.get("prior_open") or {}  # {host: {"tcp": [ports], "udp": [ports]}}
    if not prior:
        return None
    tcp = sorted({p for v in prior.values() for p in v.get("tcp", [])})
    udp = sorted({p for v in prior.values() for p in v.get("udp", [])})
    return cmd.nmap_services(ctx["iface"], sorted(prior), ctx["timing"], tcp, udp, ctx["job_id"], **_kw(ctx))


REGISTRY: dict[str, Check] = {c.name: c for c in (
    Check("syn", "TCP SYN port scan", "11.4.5, 11.4.6, 1.3.1, 1.3.3, 1.4.x, A1.1.4",
          lambda ctx: cmd.nmap_syn(ctx["iface"], ctx["targets"], ctx["timing"], ctx.get("tcp_ports", cmd.DEFAULT_TCP_PORTS),
                                   ctx["job_id"], **_kw(ctx))),
    Check("icmp", "ICMP echo/timestamp discovery", "11.4.5, 11.4.6",
          lambda ctx: cmd.nmap_icmp(ctx["iface"], ctx["targets"], ctx["timing"], ctx["job_id"], **_kw(ctx))),
    Check("udp", "UDP port scan", "11.4.5, 11.4.6, 1.3.1",
          lambda ctx: cmd.nmap_udp(ctx["iface"], ctx["targets"], ctx["timing"], ctx.get("udp_ports", cmd.DEFAULT_UDP_PORTS),
                                   ctx["job_id"], **_kw(ctx))),
    Check("services", "Insecure services", "1.2.5, 1.2.6, 2.2.4, 2.2.5, 2.2.7, 8.3.2",
          _services_build, _services_post, heuristics=False),
    Check("egress", "Egress to tester listener", "1.3.2, 1.4.2",
          lambda ctx: cmd.nmap_egress(ctx["iface"], ctx["egress_listener"], ctx["timing"],
                                      ctx.get("egress_ports", "1-1024"), ctx["job_id"], **_kw(ctx)),
          _egress_post, heuristics=False, per_block=False),
)}
BLOCK_ORDER = ["syn", "icmp", "udp", "services"]  # per iface x /24, services needs syn/udp results first


def process(check: str, xml_text: str, ctx: dict) -> tuple[list[dict], list[dict]]:
    c = REGISTRY[check]
    scan = nmapxml.parse(xml_text)
    rows = evidence.classify(scan)
    if c.post:
        c.post(scan, rows, ctx)
    flags = evidence.analyze(scan, rows) if c.heuristics else []
    return rows, flags
