"""Tests for the JSON exporter."""

from __future__ import annotations

import json
import sqlite3

from population_tracker.export import export
from population_tracker.protocol import BaseClass, WorldList, WorldListMember
from population_tracker.storage import _CLASS_COLUMNS, PopulationSample, PopulationStore


def test_export_produces_dashboard_json(tmp_path):
    world_list = WorldList(
        member_count=2,
        members=[
            WorldListMember(int(BaseClass.WIZARD), False, 255, 0, "", False, "A"),
            WorldListMember(int(BaseClass.PRIEST), False, 255, 0, "", False, "B"),
        ],
    )

    db = tmp_path / "pop.db"
    with PopulationStore(db) as store:
        store.record(PopulationSample.from_world_list(world_list))
        store.record(PopulationSample.failed())

    out = tmp_path / "docs" / "population.json"
    count = export(db, out)

    assert count == 2
    payload = json.loads(out.read_text())
    assert payload["classes"] == ["peasant", "warrior", "rogue", "wizard", "priest", "monk"]
    assert len(payload["samples"]) == 2

    ok, failed = payload["samples"]
    assert ok["total"] == 2 and ok["wizard"] == 1 and ok["priest"] == 1
    assert ok["active"] == 2  # both awake
    assert failed["total"] is None and failed["wizard"] is None and failed["active"] is None


def test_export_tolerates_missing_active_column(tmp_path):
    # a database created before the `active` column existed
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(db)
    class_defs = ", ".join(f"{column} INTEGER" for column in _CLASS_COLUMNS)
    conn.execute(
        f"CREATE TABLE population (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        f"recorded_at TEXT NOT NULL, total INTEGER, {class_defs})"
    )
    _insert(conn, "2026-07-15T10:00:00+00:00", 12, warrior=12)
    conn.close()

    out = tmp_path / "population.json"
    export(db, out)
    payload = json.loads(out.read_text())

    assert payload["samples"][0]["total"] == 12
    assert payload["samples"][0]["active"] is None  # column absent -> null, no crash


def _insert(conn, recorded_at, total, **classes):
    cols = ["recorded_at", "total", *_CLASS_COLUMNS]
    vals = [recorded_at, total, *(classes.get(c) for c in _CLASS_COLUMNS)]
    conn.execute(
        f"INSERT INTO population ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})",
        vals,
    )
    conn.commit()


def test_old_data_is_rolled_up_to_daily_averages(tmp_path):
    db = tmp_path / "pop.db"
    with PopulationStore(db) as store:  # create schema
        pass

    conn = sqlite3.connect(db)
    # two readings on one old day: totals 10 and 20 -> daily average 15
    _insert(conn, "2020-01-01T00:00:00+00:00", 10, warrior=4, monk=6)
    _insert(conn, "2020-01-01T12:00:00+00:00", 20, warrior=8, monk=12)
    # a whole failed old day -> null rollup
    _insert(conn, "2020-01-02T06:00:00+00:00", None)
    conn.close()

    out = tmp_path / "population.json"
    export(db, out, recent_days=30)  # 2020 data is far older than 30 days
    payload = json.loads(out.read_text())

    days = {s["recorded_at"]: s for s in payload["samples"]}
    assert days["2020-01-01T00:00:00+00:00"]["total"] == 15
    assert days["2020-01-01T00:00:00+00:00"]["warrior"] == 6
    assert days["2020-01-01T00:00:00+00:00"]["monk"] == 9
    assert days["2020-01-02T00:00:00+00:00"]["total"] is None  # all failed that day
