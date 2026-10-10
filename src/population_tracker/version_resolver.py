"""Resolves the live client version from the same DLL the official launcher ships.

The lobby handshake rejects a mismatched version, so the tracker must report
whatever the live client reports. Rather than hardcoding it and bumping by hand
on every client update, this reads it straight from the patch server.

The launcher (decompiled) fetches assets from ``BASE_URL``. Two routes matter:

- ``Unora/details`` - a small JSON list of every shipped file with its hash. Used
  to detect whether ``Chaos.Client.dll`` changed without downloading it.
- ``Unora/get/<path>`` - the file itself.

``Chaos.Client.GlobalSettings.ClientVersion`` is a compile-time ``ushort``
constant. A constant getter compiles to the IL ``ldc.i4 <n>; ret`` - bytes
``20 <n:int32-le> 2A`` - so the version is recovered by scanning the DLL for that
instruction pair and taking the one value in the plausible version range. This
avoids a .NET/ilspycmd dependency at runtime (see tools/get_client_version.py for
the ilspycmd-based manual equivalent).

Every failure path returns ``None`` so the caller can fall back to a hardcoded
default - a flaky patch server must never block a population sample.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.request
from pathlib import Path
from typing import Final

logger = logging.getLogger("population_tracker.version")

#: Last-known-good version, used when the patch server can't be reached or parsed.
#: Keep this current with the live client as a safety net for offline runs.
CLIENT_VERSION_FALLBACK: Final = 745

#: Patch server root, taken from the launcher's DEFAULT_ASSET_BASE_URL.
BASE_URL: Final = "http://unora.freeddns.org:5001/api/files/"
DETAILS_URL: Final = BASE_URL + "Unora/details"
DLL_DOWNLOAD_URL: Final = BASE_URL + "Unora/get/ChaosClient/Chaos.Client.dll"

#: How Chaos.Client.dll is keyed in the details JSON (server uses backslashes).
DLL_MANIFEST_PATH: Final = "ChaosClient\\Chaos.Client.dll"

#: Dark Ages client versions are three digits (744, 745, ...). The scan trusts a
#: match only when exactly one IL constant falls in this window, so it can never
#: silently pick the wrong number - a collision or an out-of-range version makes
#: it return None and the caller keeps the last-known value. Widen if the server
#: ever moves the version outside this range.
VERSION_MIN: Final = 700
VERSION_MAX: Final = 999

#: `ldc.i4 <int32>` (0x20) followed by `ret` (0x2A) - the body of a constant getter.
_LDC_I4_RET: Final = re.compile(rb"\x20(....)\x2a", re.DOTALL)

_DEFAULT_TIMEOUT: Final = 15.0


def resolve_client_version(cache_path: str | Path, *, timeout: float = _DEFAULT_TIMEOUT) -> int | None:
    """Returns the live client version, or None if it cannot be determined.

    Checks the cheap details endpoint first and only downloads the DLL when its
    hash is one we have not parsed before, so the steady-state cost is a single
    small JSON request.
    """
    try:
        dll_hash = _current_dll_hash(timeout)
    except (OSError, ValueError) as exc:
        logger.warning("could not reach patch server for client version: %s", exc)
        return None

    if dll_hash is None:
        logger.warning("Chaos.Client.dll not found in patch details listing")
        return None

    cache = _read_cache(cache_path)

    if dll_hash in cache:
        return cache[dll_hash]

    try:
        dll = _download(DLL_DOWNLOAD_URL, timeout)
    except OSError as exc:
        logger.warning("could not download client dll: %s", exc)
        return None

    version = _scan_version(dll)

    if version is None:
        return None

    cache[dll_hash] = version
    _write_cache(cache_path, cache)
    logger.info("resolved client version %d from patch server", version)

    return version


def _current_dll_hash(timeout: float) -> str | None:
    """Returns the server's hash for Chaos.Client.dll, or None if not listed."""
    details = json.loads(_download(DETAILS_URL, timeout))

    for entry in details:
        if entry.get("relativePath") == DLL_MANIFEST_PATH:
            return entry.get("hash")

    return None


def _scan_version(dll: bytes) -> int | None:
    """Recovers the ClientVersion constant from the DLL's IL, or None if unsure."""
    values = {int.from_bytes(m.group(1), "little") for m in _LDC_I4_RET.finditer(dll)}
    candidates = sorted(v for v in values if VERSION_MIN <= v <= VERSION_MAX)

    if len(candidates) == 1:
        return candidates[0]

    logger.warning(
        "client-version scan found %d candidates in [%d, %d] (%s); keeping fallback",
        len(candidates),
        VERSION_MIN,
        VERSION_MAX,
        candidates,
    )
    return None


def _download(url: str, timeout: float) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - fixed trusted host
        return response.read()


def _read_cache(cache_path: str | Path) -> dict[str, int]:
    try:
        return json.loads(Path(cache_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_cache(cache_path: str | Path, cache: dict[str, int]) -> None:
    try:
        Path(cache_path).write_text(json.dumps(cache), encoding="utf-8")
    except OSError as exc:
        logger.warning("could not write client-version cache: %s", exc)
