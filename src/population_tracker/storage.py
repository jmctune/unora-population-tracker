"""SQLite persistence for population samples.

One row per run in the `population` table: a UTC timestamp, the total online
count, and a per-class breakdown taken from the country list. When a run fails to
read the list (server down, bad login, timeout) a row is still written for that
run with NULL counts, so the gap is visible rather than silently missing.
"""

from __future__ import annotations

import sqlite3
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .protocol import BaseClass, WorldList

# columns mirror the classes shown in the country list
_CLASS_COLUMNS: tuple[str, ...] = tuple(cls.name.lower() for cls in BaseClass)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True, slots=True)
class PopulationSample:
    recorded_at: str
    #: None when the run failed to read the list; the class counts are then None too.
    total: int | None
    #: Players not marked AFK (see protocol.AFK_STATUSES) - i.e. at their keyboard.
    #: None on a failed run. AFK players are total - active.
    active: int | None
    class_counts: dict[str, int | None]

    @property
    def succeeded(self) -> bool:
        return self.total is not None

    @classmethod
    def from_world_list(cls, world_list: WorldList, exclude_name: str | None = None) -> "PopulationSample":
        members = world_list.members
        total = world_list.member_count

        if exclude_name:
            # the tracker logs in a real character to read the list, and the server
            # includes that own client in the count (WorldServer sends every online
            # Aisling). Drop it so the stats reflect other players, not the probe.
            target = exclude_name.casefold()
            members = [member for member in members if member.name.casefold() != target]
            total = max(0, total - 1)

        counts = Counter(member.class_name for member in members)

        return cls(
            recorded_at=_utc_now(),
            total=total,
            active=sum(1 for member in members if not member.is_afk),
            class_counts={column: counts.get(column, 0) for column in _CLASS_COLUMNS},
        )

    @classmethod
    def failed(cls) -> "PopulationSample":
        """A sample marking a run that could not read the list; every count is NULL."""
        return cls(
            recorded_at=_utc_now(),
            total=None,
            active=None,
            class_counts={column: None for column in _CLASS_COLUMNS},
        )


class PopulationStore:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._connection = sqlite3.connect(self._path)
        # DELETE (rollback) journal keeps everything in the single .db file, so the
        # committed database is self-contained with no -wal/-shm sidecars. This also
        # converts any pre-existing WAL database back on open.
        self._connection.execute("PRAGMA journal_mode=DELETE")
        self._create_schema()

    def _create_schema(self) -> None:
        # columns are nullable so failed runs can record NULL counts
        columns = ", ".join(f"{column} INTEGER" for column in _CLASS_COLUMNS)
        self._connection.execute(
            f"""
            CREATE TABLE IF NOT EXISTS population (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recorded_at TEXT NOT NULL,
                total INTEGER,
                active INTEGER,
                {columns}
            )
            """
        )
        self._connection.commit()
        self._migrate_drop_not_null()
        self._migrate_add_active()

    def _migrate_add_active(self) -> None:
        """Adds the `active` column to databases created before it existed."""
        info = self._connection.execute("PRAGMA table_info(population)").fetchall()
        if any(name == "active" for _, name, *_ in info):
            return

        with self._connection:
            self._connection.execute("ALTER TABLE population ADD COLUMN active INTEGER")

    def _migrate_drop_not_null(self) -> None:
        """Rebuilds the table if an older schema declared total/class columns NOT NULL."""
        info = self._connection.execute("PRAGMA table_info(population)").fetchall()
        # PRAGMA columns: (cid, name, type, notnull, dflt_value, pk)
        nullable_targets = {"total", *_CLASS_COLUMNS}
        needs_rebuild = any(name in nullable_targets and notnull for _, name, _, notnull, _, _ in info)

        if not needs_rebuild:
            return

        all_columns = ["recorded_at", "total", *_CLASS_COLUMNS]
        column_list = ", ".join(all_columns)
        new_columns = ", ".join(f"{column} INTEGER" for column in _CLASS_COLUMNS)

        with self._connection:
            self._connection.execute(
                f"""
                CREATE TABLE population_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recorded_at TEXT NOT NULL,
                    total INTEGER,
                    {new_columns}
                )
                """
            )
            self._connection.execute(
                f"INSERT INTO population_new (id, {column_list}) "
                f"SELECT id, {column_list} FROM population"
            )
            self._connection.execute("DROP TABLE population")
            self._connection.execute("ALTER TABLE population_new RENAME TO population")

    def record(self, sample: PopulationSample) -> None:
        columns = ["recorded_at", "total", "active", *_CLASS_COLUMNS]
        placeholders = ", ".join("?" for _ in columns)
        values = [
            sample.recorded_at,
            sample.total,
            sample.active,
            *(sample.class_counts[c] for c in _CLASS_COLUMNS),
        ]

        self._connection.execute(
            f"INSERT INTO population ({', '.join(columns)}) VALUES ({placeholders})",
            values,
        )
        self._connection.commit()

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "PopulationStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
