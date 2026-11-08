# SegMap

PCI DSS v4.0.1 network segmentation testing and visualization (11.4.5 / 11.4.6, plus 1.3.1, 1.3.2, 1.3.3,
1.4.x, 2.2.4/2.2.5/2.2.7, 8.3.2, 11.5.1 evidence). SegMap connects to your Linux test machines over SSH,
runs nmap from every interface toward tagged scope networks, and draws an interface → /24 reachability
graph from **strong evidence only**.

## Why not plain `nmap -sn`

Host discovery counts *any* reply, including a firewall's RST, a proxy-ARP router or a SYN proxy, so whole
/24s show as "up". In a segmentation test a firewall-generated RST proves segmentation *works*. SegMap:

- never uses TCP ping probes / `-PA`; parses `-oX` XML only;
- counts a host as reachable only on TCP `open` (SYN-ACK), ICMP `echo-reply`/`timestamp-reply` from the
  target itself, or UDP `open`;
- stores RST / port-unreach / ARP replies as **weak** ("unverified"), never a solid arrow;
- flags per-/24 middlebox patterns: uniform-TTL RST responders, SYN proxies (downgraded), transparent
  proxies on single ports, ICMP-answering middleboxes (downgraded), proxy ARP.

Acceptance check (covered by tests, and verified against a live network): scanning TEST-NET-1
`192.0.2.0/24` behind a RST-answering firewall gives 0 strong findings and 0 solid arrows.

## Layout

```
backend/   Python 3.12+ FastAPI app (segmap/) + pytest suite (tests/, fixtures/*.xml)
frontend/  React 18 + Vite + React Flow + ELK + xterm.js + Zustand
tools/     egress_listener.py, which runs on a VPS you control (egress check, 1.3.2)
```

## Setup

```bash
# backend
cd backend
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/pytest                         # unit + job-queue tests
SEGMAP_IT=1 .venv/bin/pytest tests/test_integration_ssh.py   # optional: real SSH + local nmap, probes 192.0.2.0/30

# frontend (build once; the backend serves frontend/dist)
cd ../frontend && npm install && npm run build

# run
cd ../backend && .venv/bin/python -m segmap      # http://127.0.0.1:8765
```

Dev mode with hot reload: run the backend, then `cd frontend && npm run dev` (http://127.0.0.1:5173, proxies
`/api` and `/ws`).

Environment:

| var | default | meaning |
|---|---|---|
| `SEGMAP_HOST` / `SEGMAP_PORT` | `127.0.0.1` / `8765` | bind address (keep it on localhost) |
| `SEGMAP_DATA` | `backend/data` | SQLite DB, job logs, key file (dir created 0700) |
| `SEGMAP_KEY` | – | Fernet key for credentials; else `data/secret.key` is generated with 0600 |
| `SEGMAP_KILL_GRACE` | `3` | seconds between SIGTERM and SIGKILL |
| `SEGMAP_ALLOWED_HOSTS` | – | extra Host header names if you deliberately bind elsewhere |

## Remote test machine prerequisites

Kali/Debian-like Linux with `nmap`, `iproute2` (`ip`) and util-linux `setsid`. Raw sockets are required
(`-sS`, ICMP), so you need one of:

- log in as root, or
- a user with sudo (password given in the UI, sent over stdin with `sudo -S`, never on a command line), or
- capabilities on the real nmap binary:
  `sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which nmap))`
  (on Kali `/usr/bin/nmap` is a wrapper script, so set the caps on `/usr/lib/nmap/nmap`). SegMap then adds `--privileged`.

After you connect, SegMap checks the nmap version, the privilege mode, `ip` and `setsid`, discovers interfaces (`ip -j addr`,
falling back to `ip -o addr`), and collects routes and neighbours. Errors are shown on the machine card.

## Using it

1. **Add a machine** (password or private key, optional sudo password). On first connect, compare the host key fingerprint
   and click *Trust & connect*. If the key changes later, SegMap refuses to connect and shows a red warning.
2. **Scope**: paste CIDRs, IPs or ranges (`10.0.0.0/24`, `10.0.1.5`, `10.0.2.10-50`), or upload a list, and assign a tag.
   Built-in tags: `CDE`, `connected-to`, `non-CDE`, `out-of-scope`; you can add your own (e.g. `wireless`). Larger networks are
   split into /24 boxes. One /24 can carry only one tag. Entries larger than /16 are rejected.
3. **Interface zones** are derived from the scope (interface IP inside a tagged CIDR). Override them per interface. The zone
   decides arrow colour: red = critical (e.g. non-CDE or out-of-scope reaching CDE, CDE reaching out-of-scope),
   orange = high.
4. **Scan profile**: checks, `-T0..-T5`, TCP/UDP ports, `--max-rate` / `--max-retries` / `--host-timeout`, egress listener.
   Runs estimated at more than 1 h ask for confirmation first.
5. **Run**: ▶ on an interface (all its jobs, one after another), *Run machine* (all its interfaces, one after another), or
   tick interfaces and use *Run selected*. Different machines run in parallel. The job unit is one interface × one /24 × one check,
   so the graph updates block by block.
6. **Kill**: ■ per job, or **MASTER KILL** (kills everything running, cancels the queue). Each scan runs as
   `setsid -w sh -c 'echo SEGMAP_PGID=$$; exec nmap …'`; killing sends `kill -TERM -- -PGID` over a separate SSH exec, then
   `-KILL` after the grace period.
7. **Inspect**: click an arrow to see the hosts, ports, reason, TTL, service, evidence, insecure-service issues with PCI
   references, and the producing job; export it as CSV. Click a job to see its live or recorded terminal output and exact command.
8. **Export**: graph PNG/SVG, findings JSON/CSV, scan timeline CSV (11.5.1: give it to the SOC), audit log CSV.

### Checks

| check | requirement | rule |
|---|---|---|
| TCP SYN (`-Pn -sS`) | 11.4.5/11.4.6, 1.3.1, 1.3.3, 1.4.x, A1.1.4 | only `open`/syn-ack is strong |
| ICMP (`-sn -PE -PP --disable-arp-ping`) | 11.4.5/11.4.6 | only echo/timestamp reply is strong |
| UDP (`-sU`, off by default) | 11.4.5, 1.3.1 | only `open`/udp-response is strong |
| Insecure services (`-sV` + safe NSE on strong-open ports) | 1.2.5/1.2.6, 2.2.4/2.2.5/2.2.7, 8.3.2 | telnet, FTP/anon FTP, r-services, TFTP, HTTP without TLS, LDAP without TLS, SNMP v1/v2c, VNC without auth/TLS, open X11, NFS exports, Redis/Mongo without auth, SMBv1, weak SSH algorithms, native RDP |
| Egress (`-sS --script banner` to your listener) | 1.3.2, 1.4.2 | strong only if the banner carries your token; runs from CDE-zone interfaces |

Egress listener: see `tools/egress_listener.py` (iptables REDIRECT of all ports to one socket that answers with
`SEGMAP-EGRESS <token>`).

Adding a check: in `backend/segmap/checks.py` write `build(ctx) -> argv`, and optionally `post(scan, rows, ctx)`, then register it.
Argument building stays in `commands.py`.

## Security notes

- Binds to 127.0.0.1. A Host-header and Origin guard blocks DNS-rebinding and cross-site requests.
- SSH credentials are Fernet-encrypted at rest. Secrets never appear in argv, logs or the audit table.
- No shell injection: every remote command is an argv list built in `commands.py` (interfaces checked against the discovered
  list, targets parsed with `ipaddress`, ports/timing/options validated), then `shlex.join`ed. The scan's stdin is
  `/dev/null`, so a sudo password can never reach nmap's interactive keys.
- Every remote exec, including prereq, kill, cat and rm, is written to the audit log (time, OS user, machine, command).
- After a backend restart, jobs still marked running are reconciled: if the process group is alive it is killed, otherwise
  the job is marked failed. Queued jobs are cancelled and never auto-started.

## Not in v1

IPv6 (note: dual-stack bypass of IPv4-only filtering is a real finding class), Windows test machines, exploitation /
vulnerability scanning, multi-user auth, automatic PASS/FAIL against a flow matrix (`SEVERITY` in `app.py` is the single place
to replace with one). Later candidates from the Phase 0 catalog: TLS/cert checks (4.2.1), NTP (10.6), anti-spoofing (1.4.3),
wireless AP detection (11.2.1), retest diff (11.4.4), inventory diff (12.5.1), unknown-network discovery (12.5.2).
