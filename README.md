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
- Job queue with live terminal output, per-job kill and master kill
- Exports: PNG/SVG, findings JSON/CSV, scan timeline CSV (11.5.1), audit log CSV

## Quick start

Requirements: Python 3.12+, Node 18+, and on each test machine `nmap`, `iproute2`, `setsid` plus root,
sudo or nmap capabilities.

```bash
./start.sh
```

On the first run this creates the Python venv and builds the frontend. It then starts the app on
`127.0.0.1` with a random free 5-digit port and prints the URL. To use a fixed port:
`SEGMAP_PORT=12345 ./start.sh`.

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
