# SegMap

Network segmentation testing and visualization for **PCI DSS v4.0.1** (11.4.5 / 11.4.6).

SegMap connects to your Linux test machines over SSH, runs nmap from every interface toward tagged scope
networks (CDE, connected-to, non-CDE, out-of-scope, custom), and draws an interface → /24 reachability graph
built from **strong evidence only** (SYN-ACK, ICMP echo/timestamp reply, UDP response). Firewall RSTs,
SYN proxies, proxy ARP and ICMP-answering middleboxes are flagged, never drawn as reachability.

## Features

- Machines and interfaces discovered over SSH (password or key, optional sudo; TOFU host keys)
- Scope by CIDR / IP / range, split into /24 boxes, one tag per /24
- Checks: TCP SYN, ICMP, UDP, insecure services (2.2.x / 8.3.2), egress from CDE (1.3.2)
- Graph colored by severity (source zone × target tag), edge details with per-host evidence
- Job queue with live terminal output, pause/resume, per-job kill and master kill; survives restarts and lost connections
- Exports: PNG/SVG, findings JSON/CSV, scan timeline CSV (11.5.1), audit log CSV

## Quick start

Requirements: Python 3.12+, Node 18+, and on each test machine `nmap`, `iproute2`, `setsid` plus root,
sudo or nmap capabilities.

```bash
./start.sh            # build if missing or stale, start in background, print URL
./start.sh status     # running? URL, PID, active scan jobs
./start.sh logs       # follow the log
./start.sh stop
./start.sh --debug    # foreground with live debug logs (app + SSH); Ctrl+C stops
./start.sh rebuild    # clean reinstall of venv + frontend build, then start (after git pull)
./start.sh purge      # delete DB, secret key, logs and all build output (asks first)
```

The app listens on `127.0.0.1`, on the last used port if it is free, otherwise a random 5-digit port
(fixed port: `SEGMAP_PORT=12345 ./start.sh`). `start` rebuilds the frontend automatically when its sources
are newer than the build, so `git pull && ./start.sh restart` is enough for most updates.

Queues live only on this host. Stopping the backend pauses them (a running scan goes back to the queue as never
started) and they wait for **Resume** after the next start; the same happens per machine when its SSH connection drops.
`stop`, `restart`, `rebuild` and `purge` refuse while a scan is running, to avoid throwing that work away; add
`--force` to override.

Tests:

```bash
cd backend && .venv/bin/pip install -e '.[test]' && .venv/bin/pytest
```

## Layout

```
backend/   FastAPI app (segmap/) + pytest suite
frontend/  React + Vite + React Flow + xterm.js
tools/     egress_listener.py for the egress check (runs on a VPS you control)
docs/      GUIDE.md: setup, checks, usage, security notes
```

## Security

Binds to localhost only. SSH credentials are encrypted at rest, sudo passwords go over stdin only, every
remote command is validated and written to an audit log. See [docs/GUIDE.md](docs/GUIDE.md).

## Disclaimer

Only scan networks you are authorized to test. PCI DSS requirement references should be checked against
the official PCI SSC documents before they go into a report.
