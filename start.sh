#!/usr/bin/env bash
# SegMap control script.
#
#   ./start.sh [start]     build if missing/stale, run in background, print URL
#   ./start.sh --debug     same, but in the foreground with debug logs (Ctrl+C stops)
#   ./start.sh stop        stop the backend (queues are paused and kept; a running scan is interrupted)
#   ./start.sh restart     stop + start
#   ./start.sh status      running? URL, PID, active jobs
#   ./start.sh logs        follow the background log
#   ./start.sh rebuild     clean reinstall of backend venv + frontend build, then start (use after git pull)
#   ./start.sh purge       delete database, secret key, logs and all build output (asks first)
#
#   --force   stop/restart/rebuild/purge even while a scan is running
#   --yes     purge without the confirmation prompt
#   SEGMAP_PORT=12345      fixed port (default: last used port if free, else random 5-digit)
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

DATA=${SEGMAP_DATA:-$PWD/backend/data}
PIDF=$DATA/segmap.pid PORTF=$DATA/segmap.port LOG=$DATA/segmap.log
PY=$PWD/backend/.venv/bin/python

usage() { sed -n '3,16p' "$0" | sed 's/^# \{0,1\}//'; }

cmd=start debug="" force="" yes=""
for a in "$@"; do
  case $a in
    start | stop | restart | status | logs | rebuild | purge) cmd=$a ;;
    --debug) debug=1 ;;
    --force) force=1 ;;
    --yes | -y) yes=1 ;;
    -h | --help | help) usage; exit 0 ;;
    *) echo "unknown argument: $a" >&2; usage >&2; exit 2 ;;
  esac
done

running() { [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null && grep -qa segmap "/proc/$(cat "$PIDF")/cmdline"; }
url() { echo "http://${SEGMAP_HOST:-127.0.0.1}:$(cat "$PORTF")"; }

active_jobs() {
  curl -fsS "$(url)/api/state" 2>/dev/null |
    "$PY" -c 'import json,sys; print(sum(j["status"] == "running" for j in json.load(sys.stdin)["jobs"]))' 2>/dev/null ||
    echo 0
}

# Shutdown pauses every queue (kept for Resume) but interrupts a running scan, which then restarts from
# scratch on Resume; don't throw that work away by accident.
guard() {
  running || return 0
  local n
  n=$(active_jobs)
  if [ "$n" -gt 0 ] && [ -z "$force" ]; then
    echo "$n scan(s) running; stopping interrupts them (queues are kept, paused). Wait, or add --force." >&2
    exit 1
  fi
}

# Install/build only what is missing or older than its sources (so a git pull is picked up automatically).
build() {
  if [ ! -x "$PY" ] || [ backend/pyproject.toml -nt backend/.venv/.installed ]; then
    echo "backend: installing..."
    [ -x "$PY" ] || python3 -m venv backend/.venv
    "$PY" -m pip install -q -e backend
    touch backend/.venv/.installed
  fi
  if [ ! -d frontend/node_modules ] || [ frontend/package-lock.json -nt frontend/node_modules/.package-lock.json ]; then
    echo "frontend: installing packages..."
    (cd frontend && npm ci --no-audit --no-fund --loglevel=error)
  fi
  if [ ! -f frontend/dist/index.html ] || [ -n "$(find frontend/src frontend/index.html frontend/vite.config.js \
    frontend/package-lock.json -newer frontend/dist/index.html -print -quit)" ]; then
    echo "frontend: building..."
    (cd frontend && npx vite build --logLevel error)
  fi
}

pick_port() {
  in_use() { ss -ltnH "sport = :$1" | grep -q .; }
  [ -n "${SEGMAP_PORT:-}" ] && return
  local last p
  last=$(cat "$PORTF" 2>/dev/null || true)
  if [ -n "$last" ] && ! in_use "$last"; then SEGMAP_PORT=$last; return; fi
  for _ in $(seq 50); do
    p=$(shuf -i 10000-65535 -n 1)
    in_use "$p" || { SEGMAP_PORT=$p; return; }
  done
  echo "no free port found" >&2; exit 1
}

do_start() {
  if running; then
    [ -n "$debug" ] && { echo "already running in background ($(url)); ./start.sh stop first, or ./start.sh logs" >&2; exit 1; }
    echo "already running: $(url)"; return 0
  fi
  build
  mkdir -p "$DATA" && chmod 700 "$DATA"
  pick_port
  export SEGMAP_PORT
  echo "$SEGMAP_PORT" >"$PORTF"
  if [ -n "$debug" ]; then
    echo "SegMap (debug, Ctrl+C stops; queues are kept, paused): $(url)"
    cd backend && SEGMAP_LOG_LEVEL=debug exec "$PY" -m segmap
  fi
  [ -f "$LOG" ] && mv "$LOG" "$LOG.1"
  # new session (survives terminal close / Ctrl+C); the wrapper records its own PID, then becomes python
  (cd backend && exec setsid bash -c 'echo $$ >"$1"; exec "$2" -m segmap' _ "$PIDF" "$PY") >>"$LOG" 2>&1 </dev/null &
  sleep 0.2
  for _ in $(seq 40); do
    if curl -fs -o /dev/null "$(url)/api/profile"; then
      echo "SegMap running: $(url)"
      echo "  ./start.sh logs | status | stop"
      return 0
    fi
    kill -0 "$(cat "$PIDF")" 2>/dev/null || break
    sleep 0.5
  done
  echo "SegMap failed to start; last log lines:" >&2
  tail -20 "$LOG" >&2
  rm -f "$PIDF"
  exit 1
}

do_stop() {
  if ! running; then rm -f "$PIDF"; echo "not running"; return 0; fi
  guard
  local p
  p=$(cat "$PIDF")
  kill -TERM "$p"
  for _ in $(seq 45); do kill -0 "$p" 2>/dev/null || break; sleep 1; done # shutdown kill of scans waits up to 30 s
  kill -0 "$p" 2>/dev/null && { echo "still alive after 45 s, sending SIGKILL"; kill -KILL "$p"; }
  rm -f "$PIDF"
  echo "stopped"
}

case $cmd in
  start) do_start ;;
  stop) do_stop ;;
  restart) guard; do_stop; do_start ;;
  status)
    if running; then echo "running: $(url)  pid $(cat "$PIDF")  scans running: $(active_jobs)"; else echo "stopped"; fi ;;
  logs)
    [ -f "$LOG" ] || { echo "no log yet ($LOG)" >&2; exit 1; }
    tail -n 100 -f "$LOG" ;;
  rebuild)
    guard; do_stop
    rm -rf backend/.venv backend/*.egg-info frontend/node_modules frontend/dist
    do_start ;;
  purge)
    guard
    echo "This deletes the SegMap database (all findings, jobs, audit log, saved SSH credentials),"
    echo "secret.key, logs, backend venv, node_modules and the frontend build in $PWD."
    echo "It cannot be undone. Export anything you need first."
    if [ -z "$yes" ]; then
      read -r -p "Type 'purge' to confirm: " ans
      [ "$ans" = purge ] || { echo "aborted"; exit 1; }
    fi
    do_stop
    # only known files, never rm -rf "$DATA" itself (SEGMAP_DATA may point anywhere)
    rm -rf "$DATA"/segmap.db "$DATA"/segmap.db-* "$DATA"/secret.key "$DATA"/logs "$DATA"/segmap.port "$DATA"/segmap.log*
    rmdir "$DATA" 2>/dev/null || true
    rm -rf backend/.venv backend/*.egg-info frontend/node_modules frontend/dist
    echo "purged" ;;
esac
