"""Command-line entry point: log in once, record the population to SQLite, log off.

Credentials and host come from CLI flags or the environment:

    DA_HOST, DA_PORT, DA_NAME, DA_PASSWORD, DA_SERVER_ID

Run:  py -3.14 -m population_tracker --host 127.0.0.1 --port 4200 --name Bob --password secret

Runs a single login, so schedule it (cron / Task Scheduler) for periodic samples.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

from .client import Config, Credentials, DarkAgesClient
from .storage import PopulationSample, PopulationStore
from .version_resolver import CLIENT_VERSION_FALLBACK, resolve_client_version

logger = logging.getLogger("population_tracker")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="population_tracker", description=__doc__)
    parser.add_argument("--host", default=os.environ.get("DA_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("DA_PORT", "4200")))
    parser.add_argument("--name", default=os.environ.get("DA_NAME"))
    parser.add_argument("--password", default=os.environ.get("DA_PASSWORD"))
    parser.add_argument(
        "--server-id",
        type=int,
        default=int(os.environ["DA_SERVER_ID"]) if os.environ.get("DA_SERVER_ID") else None,
        help="server table id to select; defaults to the first server offered",
    )
    parser.add_argument(
        "--client-version",
        type=int,
        default=int(os.environ["DA_CLIENT_VERSION"]) if os.environ.get("DA_CLIENT_VERSION") else None,
        help="version reported to the lobby; must match the live client. "
        "if omitted (and DA_CLIENT_VERSION unset), it is read from the patch server "
        f"at runtime, falling back to {CLIENT_VERSION_FALLBACK}",
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="seconds to allow for the whole login")
    parser.add_argument("--database", default=os.environ.get("DA_DATABASE", "population.db"))
    parser.add_argument("--log-level", default=os.environ.get("DA_LOG_LEVEL", "INFO"))

    args = parser.parse_args()

    if not args.name or not args.password:
        parser.error("character name and password are required (--name/--password or DA_NAME/DA_PASSWORD)")

    return args


async def _run(args: argparse.Namespace) -> int:
    config = Config(
        host=args.host,
        port=args.port,
        credentials=Credentials(name=args.name, password=args.password),
        client_version=args.client_version,
        server_id=args.server_id,
        timeout=args.timeout,
    )

    client = DarkAgesClient(config)

    try:
        world_list = await client.fetch()
        # exclude our own probe character - the server counts it in the list
        sample = PopulationSample.from_world_list(world_list, exclude_name=config.credentials.name)
    except (OSError, asyncio.TimeoutError, RuntimeError) as exc:
        # still record the run so the hour shows a gap rather than going missing
        logger.error("failed to read population: %s", exc)
        sample = PopulationSample.failed()

    with PopulationStore(args.database) as store:
        store.record(sample)

    if sample.succeeded:
        breakdown = " ".join(f"{name}={count}" for name, count in sample.class_counts.items() if count)
        logger.info("population online=%d active=%d %s", sample.total, sample.active, breakdown)
    else:
        logger.info("recorded a failed run (NULL counts)")

    return 0


def _resolve_version(args: argparse.Namespace) -> int:
    """Returns the explicit version if given, else reads it from the patch server."""
    if args.client_version is not None:
        return args.client_version

    cache = Path(args.database).expanduser().resolve().parent / ".client-version-cache.json"
    version = resolve_client_version(cache)

    if version is None:
        logger.warning("using fallback client version %d", CLIENT_VERSION_FALLBACK)
        return CLIENT_VERSION_FALLBACK

    return version


def main() -> None:
    args = _parse_args()
    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    args.client_version = _resolve_version(args)

    try:
        sys.exit(asyncio.run(_run(args)))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
