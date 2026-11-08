import os
from pathlib import Path

DATA = Path(os.environ.get("SEGMAP_DATA", Path(__file__).resolve().parents[1] / "data"))
HOST = os.environ.get("SEGMAP_HOST", "127.0.0.1")
PORT = int(os.environ.get("SEGMAP_PORT", "8765"))
KILL_GRACE = float(os.environ.get("SEGMAP_KILL_GRACE", "3"))
FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
