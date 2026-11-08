#!/usr/bin/env bash
# Start SegMap on 127.0.0.1 with a random free 5-digit port (override: SEGMAP_PORT=12345 ./start.sh)
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

[ -x backend/.venv/bin/python ] || { python3 -m venv backend/.venv && backend/.venv/bin/pip install -q -e backend; }
[ -f frontend/dist/index.html ] || (cd frontend && npm install && npm run build)

in_use() { ss -ltnH "sport = :$1" | grep -q .; }
if [ -z "${SEGMAP_PORT:-}" ]; then
  for _ in $(seq 50); do
    p=$(shuf -i 10000-65535 -n 1)
    in_use "$p" || { SEGMAP_PORT=$p; break; }
  done
fi
[ -n "${SEGMAP_PORT:-}" ] || { echo "no free port found" >&2; exit 1; }
export SEGMAP_PORT

echo "SegMap: http://127.0.0.1:$SEGMAP_PORT"
cd backend && exec .venv/bin/python -m segmap
