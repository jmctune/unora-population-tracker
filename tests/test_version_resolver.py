"""Tests for reading the client version off the patch server.

No network: the download layer is monkeypatched with a fake server that serves a
details listing and a synthetic DLL whose IL carries a known version constant.
"""

from __future__ import annotations

import json

import pytest

from population_tracker import version_resolver as vr


def _ldc_i4_ret(value: int) -> bytes:
    """The IL a constant getter compiles to: `ldc.i4 <value>; ret`."""
    return b"\x20" + value.to_bytes(4, "little") + b"\x2a"


def _fake_dll(version: int, *, decoys: tuple[int, ...] = (255, 4200)) -> bytes:
    """A blob shaped like the real DLL: the version plus out-of-range constants."""
    body = b"MZ" + b"\x00" * 64
    for d in decoys:
        body += _ldc_i4_ret(d)
    body += _ldc_i4_ret(version)
    return body


def test_scan_finds_unique_in_range_version():
    assert vr._scan_version(_fake_dll(745)) == 745


def test_scan_ignores_out_of_range_constants():
    # only decoys, no value in [700, 999]
    assert vr._scan_version(_fake_dll(4200, decoys=(255, 12345))) is None


def test_scan_rejects_ambiguous_match():
    # two distinct in-range constants -> cannot tell which is the version
    assert vr._scan_version(_fake_dll(745, decoys=(800,))) is None


def _install_fake_server(monkeypatch, dll: bytes, *, dll_hash: str = "HASH-1"):
    calls: dict[str, int] = {"details": 0, "dll": 0}
    details = json.dumps(
        [
            {"relativePath": "national.dat", "hash": "OTHER"},
            {"relativePath": vr.DLL_MANIFEST_PATH, "hash": dll_hash},
        ]
    ).encode()

    def fake_download(url: str, timeout: float) -> bytes:
        if url == vr.DETAILS_URL:
            calls["details"] += 1
            return details
        if url == vr.DLL_DOWNLOAD_URL:
            calls["dll"] += 1
            return dll
        raise AssertionError(f"unexpected url {url}")

    monkeypatch.setattr(vr, "_download", fake_download)
    return calls


def test_resolve_downloads_and_caches(tmp_path, monkeypatch):
    cache = tmp_path / "cache.json"
    calls = _install_fake_server(monkeypatch, _fake_dll(745))

    assert vr.resolve_client_version(cache) == 745
    assert calls == {"details": 1, "dll": 1}
    assert json.loads(cache.read_text()) == {"HASH-1": 745}


def test_resolve_uses_cache_on_second_call(tmp_path, monkeypatch):
    cache = tmp_path / "cache.json"
    calls = _install_fake_server(monkeypatch, _fake_dll(745))

    vr.resolve_client_version(cache)
    vr.resolve_client_version(cache)

    # details is checked each time (cheap), but the DLL is downloaded only once
    assert calls == {"details": 2, "dll": 1}


def test_resolve_redownloads_when_hash_changes(tmp_path, monkeypatch):
    cache = tmp_path / "cache.json"
    _install_fake_server(monkeypatch, _fake_dll(745), dll_hash="HASH-1")
    assert vr.resolve_client_version(cache) == 745

    calls = _install_fake_server(monkeypatch, _fake_dll(746), dll_hash="HASH-2")
    assert vr.resolve_client_version(cache) == 746
    assert calls["dll"] == 1
    assert json.loads(cache.read_text()) == {"HASH-1": 745, "HASH-2": 746}


def test_resolve_returns_none_when_server_unreachable(tmp_path, monkeypatch):
    def boom(url: str, timeout: float) -> bytes:
        raise OSError("connection refused")

    monkeypatch.setattr(vr, "_download", boom)
    assert vr.resolve_client_version(tmp_path / "cache.json") is None


def test_resolve_returns_none_when_dll_missing_from_details(tmp_path, monkeypatch):
    def only_details(url: str, timeout: float) -> bytes:
        if url == vr.DETAILS_URL:
            return json.dumps([{"relativePath": "national.dat", "hash": "X"}]).encode()
        raise AssertionError("should not download dll")

    monkeypatch.setattr(vr, "_download", only_details)
    assert vr.resolve_client_version(tmp_path / "cache.json") is None
