import uvicorn

from . import config

uvicorn.run("segmap.app:app", host=config.HOST, port=config.PORT)
