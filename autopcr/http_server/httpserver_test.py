from ..db.dbstart import db_start
import asyncio


async def main():
    await db_start()


asyncio.run(main())

new_loop = asyncio.new_event_loop()
asyncio.set_event_loop(new_loop)

from ..module.crons import queue_crons
from .httpserver import HttpServer

queue_crons()
server = HttpServer(port=13200)
server.run_forever(asyncio.get_event_loop())
