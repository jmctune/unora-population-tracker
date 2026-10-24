"""Reads the client version out of the shipped Chaos client binary.

The lobby handshake rejects a mismatched version, so the tracker's
`--client-version` must track whatever the live client ships. The source repo
(Chaos.Client) lags the shipped build, so the source is not authoritative - the
value has to come from the compiled DLL.

`GlobalSettings.ClientVersion` is a compile-time `ushort` constant. This
decompiles just that type with ilspycmd and parses the number out, so a client
update becomes a one-line lookup instead of a manual reverse-engineer.

Requires the ilspycmd .NET tool:
    dotnet tool install -g ilspycmd

Usage:
    py tools/get_client_version.py [path/to/Chaos.Client.dll]
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_DLL = Path(r"C:\DarkAges\Unora\ChaosClient\Chaos.Client.dll")
TYPE = "Chaos.Client.GlobalSettings"
VERSION_RE = re.compile(r"\bClientVersion\b\s*(?:=>|=)\s*(\d+)")


def read_version(dll_path: Path) -> int:
    """Decompiles GlobalSettings and returns the ClientVersion constant."""
    ilspycmd = shutil.which("ilspycmd")

    if ilspycmd is None:
        raise RuntimeError("ilspycmd not found on PATH; install with: dotnet tool install -g ilspycmd")

    result = subprocess.run(
        [ilspycmd, "-t", TYPE, str(dll_path)],
        capture_output=True,
        text=True,
        check=True,
    )

    match = VERSION_RE.search(result.stdout)

    if match is None:
        raise ValueError(f"could not find ClientVersion in {TYPE}; the field may have been renamed")

    return int(match.group(1))


def main() -> int:
    dll_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DLL

    if not dll_path.is_file():
        print(f"client dll not found at {dll_path}", file=sys.stderr)
        return 1

    try:
        version = read_version(dll_path)
    except subprocess.CalledProcessError as exc:
        print(f"ilspycmd failed:\n{exc.stderr}", file=sys.stderr)
        return 1
    except (RuntimeError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 1

    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
