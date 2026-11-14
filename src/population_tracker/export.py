"""Exports the population table to JSON for the static dashboard to fetch.

    py -3.14 -m population_tracker.export --database population.db --output docs/population.json

To keep the published file from growing without bound, samples within
``--recent-days`` are emitted at full hourly resolution and everything older is
rolled up to one averaged point per day. The database keeps every raw row; only
this exported view is trimmed. Output is compact (no whitespace).

Failed runs come through with null total and null class counts, so the dashboard
can render them as gaps; a daily rollup is null only if every sample that day failed.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import mean

from .storage import _CLASS_COLUMNS

_FIELDS: tuple[str, ...] = ("total", "active", *_CLASS_COLUMNS)


def _rollup_daily(rows: list[dict]) -> list[dict]:
    """Collapses rows to one averaged sample per UTC day (nulls ignored in the mean)."""
    by_day: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_day[row["recorded_at"][:10]].append(row)  # YYYY-MM-DD

    rollups = []
    for day in sorted(by_day):
        agg = {"recorded_at": f"{day}T00:00:00+00:00"}
        for field in _FIELDS:
            values = [r[field] for r in by_day[day] if r[field] is not None]
            agg[field] = round(mean(values)) if values else None
        rollups.append(agg)

    return rollups


def export(database: str | Path, output: str | Path, recent_days: int = 90) -> int:
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row

    try:
        # only select columns that exist, so an older database (e.g. one written
        # before `active` was added) still exports, with the absent field as null
        present = {row[1] for row in connection.execute("PRAGMA table_info(population)")}
        selected = [f for f in ("recorded_at", *_FIELDS) if f in present]
        rows = [
            {**{field: None for field in _FIELDS}, **dict(r)}
            for r in connection.execute(
                f"SELECT {', '.join(selected)} FROM population ORDER BY recorded_at ASC"
            )
        ]
    finally:
        connection.close()

    if recent_days is not None and recent_days >= 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=recent_days)
        old = [r for r in rows if datetime.fromisoformat(r["recorded_at"]) < cutoff]
        recent = [r for r in rows if datetime.fromisoformat(r["recorded_at"]) >= cutoff]
        samples = _rollup_daily(old) + recent
    else:
        samples = rows

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "classes": list(_CLASS_COLUMNS),
        "recent_days": recent_days,
        "samples": samples,
    }

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")

    return len(samples)


def main() -> None:
    parser = argparse.ArgumentParser(prog="population_tracker.export", description=__doc__)
    parser.add_argument("--database", default="population.db")
    parser.add_argument("--output", default="docs/population.json")
    parser.add_argument(
        "--recent-days",
        type=int,
        default=90,
        help="keep hourly detail for this many days; older data is rolled up to daily averages",
    )
    args = parser.parse_args()

    count = export(args.database, args.output, args.recent_days)
    print(f"exported {count} samples to {args.output}")


if __name__ == "__main__":
    main()
