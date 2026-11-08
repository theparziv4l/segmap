"""nmap -oX parser -> plain dicts. Only XML is parsed for results, never normal output."""
import xml.etree.ElementTree as ET


def _int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _port(p) -> dict:
    st = p.find("state")
    sv = p.find("service")
    sv = sv.attrib if sv is not None else {}
    st = st.attrib if st is not None else {}
    return {
        "proto": p.get("protocol"), "port": _int(p.get("portid")),
        "state": st.get("state"), "reason": st.get("reason"), "ttl": _int(st.get("reason_ttl")),
        "reason_ip": st.get("reason_ip"),
        "service": sv.get("name"), "product": sv.get("product"), "version": sv.get("version"),
        "extrainfo": sv.get("extrainfo"), "tunnel": sv.get("tunnel"),
        "scripts": {s.get("id"): s.get("output", "") for s in p.findall("script")},
    }


def parse(text: str) -> dict:
    root = ET.fromstring(text)
    hosts = []
    for h in root.findall("host"):
        st = h.find("status")
        st = st.attrib if st is not None else {}
        addrs = {a.get("addrtype"): a.get("addr") for a in h.findall("address")}
        ports_el = h.find("ports")
        hs = h.find("hostscript")
        hosts.append({
            "ip": addrs.get("ipv4"), "mac": addrs.get("mac"),
            "status": st.get("state"), "reason": st.get("reason"), "ttl": _int(st.get("reason_ttl")),
            "ports": [_port(p) for p in ports_el.findall("port")] if ports_el is not None else [],
            "extraports": [
                {"state": e.get("state"), "count": _int(e.get("count")),
                 "reasons": [r.get("reason") for r in e.findall("extrareasons")]}
                for e in (ports_el.findall("extraports") if ports_el is not None else [])],
            "hostscripts": {s.get("id"): s.get("output", "") for s in hs.findall("script")} if hs is not None else {},
        })
    rs = root.find("runstats/hosts")
    return {
        "args": root.get("args", ""),
        "scaninfo": [{"type": s.get("type"), "protocol": s.get("protocol"), "numservices": _int(s.get("numservices"))}
                     for s in root.findall("scaninfo")],
        "total": _int(rs.get("total")) if rs is not None else len(hosts),
        "hosts": [h for h in hosts if h["ip"]],
    }
