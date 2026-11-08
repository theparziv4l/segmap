"""The only module that builds remote commands. Everything is an argv list, validated,
and joined with shlex at the very edge. Never format user input into shell strings elsewhere."""
import ipaddress as ip
import re
import shlex

IFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$")
JOB_RE = re.compile(r"^[0-9a-f]{32}$")
TIMEOUT_RE = re.compile(r"^\d{1,6}(ms|s|m|h)?$")
SIGNALS = {"TERM", "KILL", "0"}

DEFAULT_TCP_PORTS = ("21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,465,587,636,993,995,"
                     "1433,1521,2049,2375,3306,3389,5432,5900,5985,5986,6379,8000,8080,8443,9200,27017")
DEFAULT_UDP_PORTS = "53,123,161,500"
SERVICE_SCRIPTS = ("ftp-anon,snmp-info,smb-protocols,vnc-info,x11-access,nfs-showmount,redis-info,"
                   "mongodb-info,http-title,ssh2-enum-algos,rdp-enum-encryption")
# Wrapper: new session => sh pid == pgid; print it, then exec the scan (stdin detached so a
# sudo password never reaches nmap's interactive keys). -w keeps setsid in the foreground.
WRAP_SH = 'echo SEGMAP_PGID=$$; exec "$@" </dev/null'
SUDO = ["sudo", "-k", "-S", "-p", ""]


# ---------- validators ----------
def check_iface(name: str, known: set[str]) -> str:
    if not isinstance(name, str) or not IFACE_RE.match(name):
        raise ValueError(f"invalid interface name {name!r}")
    if name not in known:
        raise ValueError(f"interface {name!r} not discovered on this machine")
    return name


def check_timing(t) -> int:
    if type(t) is not int or not 0 <= t <= 5:
        raise ValueError(f"timing must be int 0..5, got {t!r}")
    return t


def check_job(job_id: str) -> str:
    if not isinstance(job_id, str) or not JOB_RE.match(job_id):
        raise ValueError("invalid job id")
    return job_id


def check_target(t: str) -> str:
    try:
        return str(ip.IPv4Network(t, strict=False))
    except (ValueError, TypeError):
        raise ValueError(f"invalid target {t!r}") from None


def check_ip(a: str) -> str:
    try:
        return str(ip.IPv4Address(a))
    except (ValueError, TypeError):
        raise ValueError(f"invalid IPv4 address {a!r}") from None


def parse_ports(spec: str) -> str:
    """'22, 80-82' -> '22,80-82'; 'all' or '-' -> '-' (all ports)."""
    spec = str(spec).strip()
    if spec in ("-", "all", "-p-"):
        return "-"
    out = []
    for part in spec.split(","):
        part = part.strip()
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", part)
        if not m:
            raise ValueError(f"invalid port spec {part!r}")
        a, b = int(m[1]), int(m[2] or m[1])
        if not (1 <= a <= b <= 65535):
            raise ValueError(f"port out of range: {part!r}")
        out.append(part if m[2] else str(a))
    return ",".join(out)


def expand_ports(spec: str) -> list[int]:
    spec = parse_ports(spec)
    if spec == "-":
        return list(range(1, 65536))
    out = []
    for part in spec.split(","):
        a, _, b = part.partition("-")
        out += range(int(a), int(b or a) + 1)
    return out


def _advanced(adv: dict | None) -> list[str]:
    out: list[str] = []
    for k, v in (adv or {}).items():
        if v in (None, ""):
            continue
        if k == "max_rate" and type(v) is int and 1 <= v <= 1_000_000:
            out += ["--max-rate", str(v)]
        elif k == "max_retries" and type(v) is int and 0 <= v <= 10:
            out += ["--max-retries", str(v)]
        elif k == "host_timeout" and isinstance(v, str) and TIMEOUT_RE.match(v):
            out += ["--host-timeout", v]
        else:
            raise ValueError(f"invalid advanced option {k}={v!r}")
    return out


def remote_xml(job_id: str) -> str:
    return f"/tmp/segmap-{check_job(job_id)}.xml"


# ---------- nmap argv builders ----------
def _base(iface, timing, job_id, known_ifaces, privileged, advanced) -> list[str]:
    argv = ["nmap", "-n", "--reason", "-e", check_iface(iface, known_ifaces), f"-T{check_timing(timing)}",
            "-oX", remote_xml(job_id), "--stats-every", "30s"]
    if privileged:
        argv.append("--privileged")
    return argv + _advanced(advanced)


def _ports_arg(spec: str) -> list[str]:
    p = parse_ports(spec)
    return ["-p-"] if p == "-" else ["-p", p]


def nmap_syn(iface, targets, timing, ports, job_id, *, known_ifaces, privileged=False, advanced=None):
    return (_base(iface, timing, job_id, known_ifaces, privileged, advanced)
            + ["-Pn", "-sS"] + _ports_arg(ports) + [check_target(t) for t in targets])


def nmap_icmp(iface, targets, timing, job_id, *, known_ifaces, privileged=False, advanced=None):
    return (_base(iface, timing, job_id, known_ifaces, privileged, advanced)
            + ["-sn", "-PE", "-PP", "--disable-arp-ping"] + [check_target(t) for t in targets])


def nmap_udp(iface, targets, timing, ports, job_id, *, known_ifaces, privileged=False, advanced=None):
    return (_base(iface, timing, job_id, known_ifaces, privileged, advanced)
            + ["-Pn", "-sU"] + _ports_arg(ports) + [check_target(t) for t in targets])


def nmap_egress(iface, listener, timing, ports, job_id, *, known_ifaces, privileged=False, advanced=None):
    return (_base(iface, timing, job_id, known_ifaces, privileged, advanced)
            + ["-Pn", "-sS"] + _ports_arg(ports) + ["--script", "banner", check_ip(listener)])


def nmap_services(iface, hosts, timing, tcp_ports, udp_ports, job_id, *, known_ifaces, privileged=False,
                  advanced=None):
    def plist(ps):
        ps = sorted({int(p) for p in ps})
        if not all(1 <= p <= 65535 for p in ps):
            raise ValueError("port out of range")
        return ",".join(map(str, ps))
    if not tcp_ports and not udp_ports:
        raise ValueError("services check needs open ports")
    spec = ",".join(x for x in (tcp_ports and "T:" + plist(tcp_ports), udp_ports and "U:" + plist(udp_ports)) if x)
    scan = (["-sS"] if tcp_ports else []) + (["-sU"] if udp_ports else [])
    return (_base(iface, timing, job_id, known_ifaces, privileged, advanced)
            + ["-Pn", *scan, "-sV", "--version-light", "--script", SERVICE_SCRIPTS, "-p", spec]
            + [check_ip(h) for h in hosts])


# ---------- remote shell strings (the only shlex.join calls) ----------
def _priv(mode: str) -> list[str]:
    if mode not in ("root", "sudo", "cap"):
        raise ValueError(f"bad privilege mode {mode!r}")
    return SUDO if mode == "sudo" else []


def wrap_scan(argv: list[str], mode: str) -> str:
    return shlex.join(_priv(mode) + ["setsid", "-w", "sh", "-c", WRAP_SH, "segmap", *argv])


def kill_cmd(pgid, sig: str, mode: str) -> str:
    if type(pgid) is not int or pgid <= 1:
        raise ValueError(f"invalid pgid {pgid!r}")
    if sig not in SIGNALS:
        raise ValueError(f"invalid signal {sig!r}")
    # `env kill` = the procps binary, never a shell builtin (dash's builtin rejects `--`)
    return shlex.join(_priv(mode) + ["env", "kill", f"-{sig}", "--", f"-{pgid}"])


def cat_cmd(job_id: str, mode: str) -> str:
    return shlex.join(_priv(mode) + ["cat", remote_xml(job_id)])


def rm_cmd(job_id: str, mode: str) -> str:
    return shlex.join(_priv(mode) + ["rm", "-f", remote_xml(job_id)])


def needs_sudo_input(mode: str) -> bool:
    return mode == "sudo"


# Fixed discovery commands (no user input).
PREREQ_CMD = (
    'echo "uid=$(id -u)"; N="$(command -v nmap)"; echo "nmap=$N"; '
    'echo "nmapver=$(nmap --version 2>/dev/null | head -1)"; echo "ip=$(command -v ip)"; '
    'echo "setsid=$(command -v setsid)"; G="$(command -v getcap || echo /sbin/getcap)"; '
    'echo "caps=$("$G" "$(readlink -f "$N")" /usr/lib/nmap/nmap 2>/dev/null | tr \'\\n\' \' \')"')
SUDO_TEST_CMD = shlex.join(SUDO + ["true"])
IFACES_JSON_CMD = "ip -j addr show"
IFACES_TEXT_CMD = "ip -o addr show; ip -o link show"
ROUTES_CMD = "ip -j route show"
NEIGH_CMD = "ip -j neigh show"
