"""Evidence classification + per-block middlebox heuristics.

strong: TCP open (syn-ack), echo-reply, timestamp-reply, UDP open (udp-response)
weak:   reset, port-unreach, arp-response (from the target itself) - stored, never a solid edge
Everything else (filtered, open|filtered, ICMP errors from routers) is not evidence."""
from collections import Counter

STRONG_PORT = {"syn-ack", "udp-response"}
WEAK_PORT = {"reset", "port-unreach"}
STRONG_STATUS = {"echo-reply", "timestamp-reply"}
WEAK_STATUS = {"arp-response", "reset", "port-unreach"}

# ponytail: fixed thresholds; expose in the scan profile if testers need to tune them
MIN_HOSTS = 16          # below this a /24 is too sparse for block-level judgement
MAJORITY = 0.8          # "most" responders / identical TTL share
SYN_PROXY_MIN = 4       # hosts with every probed port open


def dominant(values) -> tuple:
    if not values:
        return None, 0.0
    v, n = Counter(values).most_common(1)[0]
    return v, n / len(values)


def _row(host, proto, port, state, reason, ttl, evidence, service=None, reason_ip=None, **detail):
    return {"host_ip": host, "protocol": proto, "port": port, "state": state, "reason": reason,
            "reason_ip": reason_ip, "ttl": ttl, "service": service, "evidence": evidence, "detail": detail}


def classify(scan: dict) -> list[dict]:
    rows = []
    for h in scan["hosts"]:
        ip = h["ip"]
        if h["reason"] in STRONG_STATUS:
            rows.append(_row(ip, "icmp", None, h["status"], h["reason"], h["ttl"], "strong"))
        elif h["reason"] in WEAK_STATUS:
            rows.append(_row(ip, "arp" if h["reason"] == "arp-response" else "ip", None, h["status"], h["reason"],
                             h["ttl"], "weak", mac=h["mac"]))
        for p in h["ports"]:
            if p["reason_ip"] not in (None, ip):
                continue  # answered by a router/firewall, not by the target
            if p["state"] == "open" and p["reason"] in STRONG_PORT:
                ev = "strong"
            elif p["state"] == "closed" and p["reason"] in WEAK_PORT:
                ev = "weak"
            else:
                continue
            extra = {k: p[k] for k in ("product", "version", "extrainfo", "tunnel", "scripts") if p[k]}
            rows.append(_row(ip, p["proto"], p["port"], p["state"], p["reason"], p["ttl"], ev, p["service"],
                             p["reason_ip"], **extra))
        for e in h["extraports"]:
            if e["state"] == "closed" and set(e["reasons"]) & WEAK_PORT:
                rows.append(_row(ip, "tcp", None, "closed", e["reasons"][0], 0, "weak", extraports=e["count"]))
    return rows


def _flag(code, message):
    return {"code": code, "message": message}


def analyze(scan: dict, rows: list[dict]) -> list[dict]:
    """Flag middlebox patterns for one job (= one /24 from one interface). Mutates rows on downgrade."""
    flags = []
    total = scan["total"]
    by_host: dict[str, list[dict]] = {}
    for r in rows:
        if r["protocol"] == "arp":
            continue  # proxy ARP has its own heuristic below
        by_host.setdefault(r["host_ip"], []).append(r)

    # 1. firewall RST / uniform TTL: nearly every responder gives only weak evidence
    weak_only = [h for h, rs in by_host.items() if all(r["evidence"] == "weak" for r in rs)]
    if len(by_host) >= MIN_HOSTS and len(weak_only) >= MAJORITY * len(by_host):
        ttls = [next((r["ttl"] for r in by_host[h] if r["ttl"]), None) for h in weak_only]
        ttl, share = dominant([t for t in ttls if t])
        if ttl is None or share >= MAJORITY:
            ttl_txt = f", identical TTL {ttl}" if ttl else ""
            flags.append(_flag("middlebox_rst", f"possible middlebox responses: {len(weak_only)} IPs answer only "
                                                f"with RST/unreachable{ttl_txt}"))

    # 2. SYN proxy: many hosts show every probed TCP port open with the same TTL -> downgrade
    probed = next((s["numservices"] for s in scan["scaninfo"] if s["protocol"] == "tcp"), 0)
    tcp_open = {h: [r for r in rs if r["protocol"] == "tcp" and r["evidence"] == "strong"] for h, rs in by_host.items()}
    tcp_open = {h: rs for h, rs in tcp_open.items() if rs}
    all_open = [h for h, rs in tcp_open.items() if probed >= 3 and len(rs) == probed]
    syn_proxy = False
    if len(all_open) >= SYN_PROXY_MIN and len(all_open) >= 0.5 * len(tcp_open):
        ttl, share = dominant([r["ttl"] for h in all_open for r in tcp_open[h]])
        if share >= MAJORITY:
            syn_proxy = True
            for h in all_open:
                for r in tcp_open[h]:
                    r["evidence"] = "weak"
                    r["detail"]["downgraded"] = "syn_proxy"
            flags.append(_flag("syn_proxy", f"possible SYN proxy: {len(all_open)} IPs show all {probed} probed "
                                            f"ports open, TTL {ttl}; downgraded to weak"))

    # 3. transparent proxy (per port): one port open on most addresses with the same TTL -> flag only
    if not syn_proxy and total >= MIN_HOSTS:
        per_port: dict[int, list[int]] = {}
        for rs in tcp_open.values():
            for r in rs:
                per_port.setdefault(r["port"], []).append(r["ttl"])
        for port, ttls in sorted(per_port.items()):
            ttl, share = dominant(ttls)
            if len(ttls) >= max(MIN_HOSTS, 0.5 * total) and share >= MAJORITY:
                flags.append(_flag("transparent_proxy", f"possible transparent/SYN proxy on tcp/{port}: "
                                                        f"{len(ttls)} IPs open, TTL {ttl}"))

    # 4. ICMP responder: (almost) every address echoes with the same TTL -> downgrade
    icmp = [r for r in rows if r["protocol"] == "icmp" and r["evidence"] == "strong"]
    if total >= MIN_HOSTS and len(icmp) >= MAJORITY * total:
        ttl, share = dominant([r["ttl"] for r in icmp])
        if share >= MAJORITY:
            for r in icmp:
                r["evidence"] = "weak"
                r["detail"]["downgraded"] = "icmp_responder"
            flags.append(_flag("icmp_responder", f"possible ICMP-answering middlebox: {len(icmp)}/{total} IPs reply, "
                                                 f"TTL {ttl}; downgraded to weak"))

    # 5. proxy ARP: many IPs on the local segment share one MAC
    mac, share = dominant([h["mac"] for h in scan["hosts"] if h["mac"]])
    n_mac = sum(1 for h in scan["hosts"] if h["mac"])
    if mac and share * n_mac >= 8 and share >= 0.5:
        flags.append(_flag("proxy_arp", f"proxy ARP: {round(share * n_mac)} IPs answer with the same MAC {mac}"))
    return flags
