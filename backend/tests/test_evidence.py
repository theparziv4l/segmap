from pathlib import Path

from segmap import checks, evidence, nmapxml

FX = Path(__file__).parent / "fixtures"


def load(name):
    return nmapxml.parse((FX / name).read_text())


def run(name, check="syn"):
    return checks.process(check, (FX / name).read_text(), {"egress_token": "tok123"})


def strong(rows):
    return [r for r in rows if r["evidence"] == "strong"]


def codes(flags):
    return {f["code"] for f in flags}


# ---------- parser ----------
def test_parse_structure():
    scan = load("open_host.xml")
    assert scan["total"] == 256
    assert scan["scaninfo"] == [{"type": "syn", "protocol": "tcp", "numservices": 4}]
    h = scan["hosts"][0]
    assert h["ip"] == "10.24.5.10" and h["reason"] == "user-set"
    p22 = h["ports"][0]
    assert (p22["proto"], p22["port"], p22["state"], p22["reason"], p22["ttl"], p22["service"]) == \
           ("tcp", 22, "open", "syn-ack", 63, "ssh")
    assert scan["hosts"][2]["ports"][0]["reason_ip"] == "10.24.5.1"
    assert scan["hosts"][3]["extraports"] == [{"state": "filtered", "count": 4, "reasons": ["no-response"]}]


def test_parse_scripts_mac_hostscripts():
    assert load("proxy_arp.xml")["hosts"][0]["mac"] == "00:50:56:AA:BB:CC"
    h = load("services.xml")["hosts"][0]
    assert "NT LM 0.12 (SMBv1)" in h["hostscripts"]["smb-protocols"]
    ftp = h["ports"][0]
    assert ftp["product"] == "vsftpd" and "Anonymous FTP login allowed" in ftp["scripts"]["ftp-anon"]
    https = [p for p in h["ports"] if p["port"] == 443][0]
    assert https["tunnel"] == "ssl"


# ---------- classifier ----------
def test_real_open_host():
    rows, flags = run("open_host.xml")
    s = strong(rows)
    assert [(r["host_ip"], r["port"], r["reason"], r["ttl"]) for r in s] == [("10.24.5.10", 22, "syn-ack", 63)]
    weak = {(r["host_ip"], r["port"]) for r in rows if r["evidence"] == "weak"}
    assert ("10.24.5.10", 80) in weak and ("10.24.5.11", 3389) in weak
    # router-generated admin-prohibited (reason_ip != host) and filtered never produce rows
    assert not [r for r in rows if r["host_ip"] == "10.24.5.12"]
    assert not [r for r in rows if r["state"] == "filtered"]
    assert flags == []


def test_acceptance_rst_everywhere_zero_strong():
    """TEST-NET-1 behind a RST-answering firewall: 0 strong findings, block flagged."""
    for fx in ("rst_everywhere.xml", "rst_extraports.xml"):
        rows, flags = run(fx)
        assert strong(rows) == []
        assert len({r["host_ip"] for r in rows}) == 256
        assert "middlebox_rst" in codes(flags)
    _, flags = run("rst_everywhere.xml")
    assert "TTL 125" in [f for f in flags if f["code"] == "middlebox_rst"][0]["message"]


def test_syn_proxy_downgraded():
    rows, flags = run("syn_proxy.xml")
    assert "syn_proxy" in codes(flags)
    assert strong(rows) == []
    assert all(r["detail"].get("downgraded") == "syn_proxy" for r in rows)


def test_transparent_proxy_flagged_not_downgraded():
    rows, flags = run("transparent_proxy.xml")
    c = codes(flags)
    assert "transparent_proxy" in c and "syn_proxy" not in c
    msgs = " ".join(f["message"] for f in flags)
    assert "tcp/80" in msgs and "tcp/443" in msgs and "tcp/22" not in msgs
    assert ("10.30.2.5", 22) in {(r["host_ip"], r["port"]) for r in strong(rows)}


def test_proxy_arp():
    rows, flags = run("proxy_arp.xml", "icmp")
    assert strong(rows) == []  # arp-response is weak
    assert all(r["reason"] == "arp-response" and r["evidence"] == "weak" for r in rows)
    assert "proxy_arp" in codes(flags)
    assert "00:50:56:AA:BB:CC" in [f for f in flags if f["code"] == "proxy_arp"][0]["message"]


def test_icmp_real_and_responder():
    rows, flags = run("icmp_real.xml", "icmp")
    assert {(r["host_ip"], r["reason"]) for r in strong(rows)} == {
        ("10.24.7.1", "echo-reply"), ("10.24.7.10", "echo-reply"), ("10.24.7.11", "timestamp-reply"),
        ("10.24.7.12", "echo-reply")}
    assert all(r["protocol"] == "icmp" and r["port"] is None for r in rows)
    assert flags == []
    rows, flags = run("icmp_responder.xml", "icmp")
    assert "icmp_responder" in codes(flags)
    assert strong(rows) == []


def test_udp_only_open_counts():
    rows, _ = run("udp.xml", "udp")
    assert [(r["port"], r["reason"]) for r in strong(rows)] == [(53, "udp-response")]
    assert [(r["port"], r["reason"]) for r in rows if r["evidence"] == "weak"] == [(161, "port-unreach")]
    assert 123 not in {r["port"] for r in rows}  # open|filtered never stored as evidence


def test_egress_token_required():
    rows, _ = run("egress.xml", "egress")
    by_port = {r["port"]: r for r in rows}
    assert by_port[443]["evidence"] == "strong" and by_port[443]["detail"]["token"] is True
    assert by_port[80]["evidence"] == "weak" and "token" in by_port[80]["detail"]["unverified"]
    assert by_port[22]["evidence"] == "weak"
    assert 8443 not in by_port


def test_services_issues():
    rows, flags = run("services.xml", "services")
    assert flags == []  # block heuristics never run on follow-up checks
    issues = {(r["host_ip"], r["port"]): [i["issue"] for i in r["detail"].get("issues", [])] for r in rows}
    h = lambda p: " | ".join(issues[("10.24.5.10", p)])  # noqa: E731
    assert "Anonymous FTP" in h(21) and "FTP" in h(21)
    assert "Telnet" in h(23)
    assert "weak SSH" in h(22)
    assert "HTTP without TLS" in h(80)
    assert "SMBv1" in h(445)
    assert "VNC without authentication" in h(5900)
    assert "Redis without authentication" in h(6379)
    assert "SNMP v1/v2c" in h(161)
    assert issues[("10.24.5.10", 443)] == []
    assert issues[("10.24.5.11", 22)] == [] and issues[("10.24.5.11", 443)] == []
    assert all(i["req"] for r in rows for i in r["detail"].get("issues", []))


def test_dominant_share():
    assert evidence.dominant([64, 64, 64, 128]) == (64, 0.75)
    assert evidence.dominant([]) == (None, 0.0)
