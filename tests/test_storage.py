"""Tests for the SQLite population store."""

from __future__ import annotations

import sqlite3

from population_tracker.protocol import BaseClass, SocialStatus, WorldList, WorldListMember
from population_tracker.storage import _CLASS_COLUMNS, PopulationSample, PopulationStore


def _member(base_class: BaseClass, name: str, social_status: int = SocialStatus.AWAKE) -> WorldListMember:
    return WorldListMember(
        base_class=int(base_class),
        is_guilded=False,
        color=255,
        social_status=int(social_status),
        title="",
        is_master=False,
        name=name,
    )


def test_sample_counts_classes():
    world_list = WorldList(
        member_count=3,
        members=[
            _member(BaseClass.WARRIOR, "A"),
            _member(BaseClass.WARRIOR, "B"),
            _member(BaseClass.WIZARD, "C"),
        ],
    )

    sample = PopulationSample.from_world_list(world_list)

    assert sample.total == 3
    assert sample.class_counts["warrior"] == 2
    assert sample.class_counts["wizard"] == 1
    assert sample.class_counts["monk"] == 0


def test_sample_excludes_own_probe_character():
    world_list = WorldList(
        member_count=3,  # server counts our own logged-in character
        members=[
            _member(BaseClass.WARRIOR, "RealPlayer", SocialStatus.AWAKE),
            _member(BaseClass.WIZARD, "Another", SocialStatus.DAY_DREAMING),  # afk
            _member(BaseClass.PEASANT, "Probe", SocialStatus.AWAKE),  # us
        ],
    )

    sample = PopulationSample.from_world_list(world_list, exclude_name="probe")  # case-insensitive

    assert sample.total == 2  # 3 reported minus our own client
    assert sample.class_counts["peasant"] == 0  # our peasant not counted
    assert sample.class_counts["warrior"] == 1
    assert sample.active == 1  # RealPlayer active; Another afk; Probe excluded


def test_sample_counts_active_excluding_afk():
    world_list = WorldList(
        member_count=5,
        members=[
            _member(BaseClass.WARRIOR, "Awake", SocialStatus.AWAKE),
            _member(BaseClass.WIZARD, "Grouped", SocialStatus.GROUPED),
            _member(BaseClass.PRIEST, "Busy", SocialStatus.DO_NOT_DISTURB),
            _member(BaseClass.MONK, "Idle", SocialStatus.DAY_DREAMING),  # afk
            _member(BaseClass.ROGUE, "Solo", SocialStatus.LONE_HUNTER),  # afk
        ],
    )

    sample = PopulationSample.from_world_list(world_list)

    assert sample.total == 5
    assert sample.active == 3  # afk (daydreaming + lone hunter) excluded


def test_store_persists_active(tmp_path):
    world_list = WorldList(
        member_count=2,
        members=[
            _member(BaseClass.WARRIOR, "Here", SocialStatus.AWAKE),
            _member(BaseClass.MONK, "Away", SocialStatus.DAY_DREAMING),
        ],
    )

    with PopulationStore(tmp_path / "pop.db") as store:
        store.record(PopulationSample.from_world_list(world_list))

    with PopulationStore(tmp_path / "pop.db") as store:
        row = store._connection.execute("SELECT total, active FROM population").fetchone()

    assert row == (2, 1)


def test_store_persists_rows(tmp_path):
    world_list = WorldList(member_count=1, members=[_member(BaseClass.MONK, "Solo")])

    with PopulationStore(tmp_path / "pop.db") as store:
        store.record(PopulationSample.from_world_list(world_list))

    # reopen to confirm it was committed to disk
    with PopulationStore(tmp_path / "pop.db") as store:
        rows = store._connection.execute("SELECT total, monk, warrior FROM population").fetchall()

    assert rows == [(1, 1, 0)]


def test_failed_sample_records_nulls(tmp_path):
    sample = PopulationSample.failed()

    assert sample.succeeded is False
    assert sample.total is None
    assert sample.active is None
    assert all(count is None for count in sample.class_counts.values())

    with PopulationStore(tmp_path / "pop.db") as store:
        store.record(sample)

    with PopulationStore(tmp_path / "pop.db") as store:
        row = store._connection.execute("SELECT total, active, warrior, monk FROM population").fetchone()

    assert row == (None, None, None, None)


def test_migrates_legacy_not_null_schema(tmp_path):
    # simulate the original schema (total + class columns NOT NULL) with one row
    path = tmp_path / "legacy.db"
    legacy = sqlite3.connect(path)
    class_defs = ", ".join(f"{column} INTEGER NOT NULL DEFAULT 0" for column in _CLASS_COLUMNS)
    legacy.execute(
        f"CREATE TABLE population (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        f"recorded_at TEXT NOT NULL, total INTEGER NOT NULL, {class_defs})"
    )
    columns = ["recorded_at", "total", *_CLASS_COLUMNS]
    legacy.execute(
        f"INSERT INTO population ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
        ["2026-07-14T16:00:00+00:00", 20, 1, 3, 1, 6, 8, 1],
    )
    legacy.commit()
    legacy.close()

    # opening through the store should rebuild the table as nullable, preserving the row
    with PopulationStore(path) as store:
        store.record(PopulationSample.failed())
        rows = store._connection.execute("SELECT total FROM population ORDER BY id").fetchall()

    assert rows == [(20,), (None,)]  # legacy row kept, new NULL row accepted


def test_migrates_schema_without_active_column(tmp_path):
    # simulate a database created before the `active` column existed
    path = tmp_path / "no_active.db"
    legacy = sqlite3.connect(path)
    class_defs = ", ".join(f"{column} INTEGER" for column in _CLASS_COLUMNS)
    legacy.execute(
        f"CREATE TABLE population (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        f"recorded_at TEXT NOT NULL, total INTEGER, {class_defs})"
    )
    columns = ["recorded_at", "total", *_CLASS_COLUMNS]
    legacy.execute(
        f"INSERT INTO population ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
        ["2026-07-15T16:00:00+00:00", 20, 1, 3, 1, 6, 8, 1],
    )
    legacy.commit()
    legacy.close()

    world_list = WorldList(member_count=1, members=[_member(BaseClass.MONK, "Here", SocialStatus.AWAKE)])
    with PopulationStore(path) as store:
        store.record(PopulationSample.from_world_list(world_list))
        rows = store._connection.execute("SELECT total, active FROM population ORDER BY id").fetchall()

    assert rows == [(20, None), (1, 1)]  # legacy row gets NULL active, new row counts it
