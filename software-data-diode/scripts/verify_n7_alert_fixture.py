"""Temporary internal-Fog Alert Engine fixture; no existing service is replaced."""
import argparse
import asyncio
import os
import re

from fastapi import HTTPException, Request
import uvicorn
from psycopg import sql

from shared.persistence.repository import PostgresRepository


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema",required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"n7_check_[a-f0-9]{32}",args.schema) or os.getenv("COVERAGE_ALERTS_ENABLED") != "true":
        raise RuntimeError("only a disposable N7 schema in the local research Alert Engine is permitted")
    class ScopedRepository(PostgresRepository):
        def _connect(self):
            connection = super()._connect()
            connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(args.schema)))
            return connection
    from app import main as service
    service.repository = ScopedRepository(os.environ["DATABASE_URL"])
    server = uvicorn.Server(uvicorn.Config(service.app,host="0.0.0.0",port=18007,log_level="warning"))
    @service.app.post("/_n7_fixture_shutdown")
    async def shutdown(request: Request):
        if request.headers.get("X-N7-Fixture") != args.schema:
            raise HTTPException(403)
        server.should_exit = True
        return {"status":"stopping"}
    task = asyncio.create_task(server.serve())
    try:
        await asyncio.wait_for(asyncio.shield(task),180)
    except asyncio.TimeoutError:
        server.should_exit = True
        await task


if __name__ == "__main__":
    asyncio.run(main())
