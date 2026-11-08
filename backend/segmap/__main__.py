import logging
import os

import uvicorn

from . import config

level = os.environ.get("SEGMAP_LOG_LEVEL", "info")
if level == "debug":  # ./start.sh --debug: app + asyncssh debug logs live on the terminal
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("aiosqlite").setLevel(logging.INFO)  # one line per SQL query is noise
uvicorn.run("segmap.app:app", host=config.HOST, port=config.PORT, log_level=level)
