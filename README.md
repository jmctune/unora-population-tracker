# unora population tracker

logs into the unora server, gathers the current population and submits it for time series viewing.

## requirements

- python 3.14+
- a character account on the target server

for development/validation only:

- .NET 10 SDK (to build the crypto validation harness)

## usage

```sh
py -3.14 -m population_tracker \
    --host 127.0.0.1 --port 4200 \
    --name MyCharacter --password secret
```

or configure via environment variables: `DA_HOST`, `DA_PORT`, `DA_NAME`,
`DA_PASSWORD`, `DA_SERVER_ID`, `DA_CLIENT_VERSION`, `DA_DATABASE`, `DA_LOG_LEVEL`.

key options:

| flag | default | meaning |
| --- | --- | --- |
| `--server-id` | first offered | which server from the lobby table to join |
| `--timeout` | `30` | seconds allowed for the whole login before giving up |
| `--database` | `population.db` | sqlite file to append the sample to |
| `--client-version` | auto | version reported during the lobby handshake; read from the patch server at runtime unless set (`DA_CLIENT_VERSION`). see [client version](#client-version) |

the process runs one login and exits `0`. a run that cannot read the list (server
down, bad login, timeout) still records a row for that run, with NULL counts, so
the gap is visible in the data rather than silently missing.

to sample on a schedule locally, run it from cron or task scheduler:

```
0 * * * * DA_NAME=Bob DA_PASSWORD=secret py -3.14 -m population_tracker --database /var/lib/unora/population.db
```

or use the built-in hourly [GitHub Action](#automation-github-action).

## data

each run appends one row to the `population` table:

```
id | recorded_at (utc iso8601) | total | active | peasant | warrior | rogue | wizard | priest | monk
```

`total` is the server-reported member count; the class columns are counted from
the country-list entries. `active` is the number of players who are *not* AFK -
the country list carries a social status per player, and the statuses
`DayDreaming` (idle) and `LoneHunter` (soloing, not interacting) mean the player
is away from the keyboard. everyone else counts as active, so away players are
`total - active`. a failed run writes NULL for `total`, `active`, and every class
column, keeping `recorded_at`.

## automation (github action)

`.github/workflows/population.yml` runs hourly, records a sample, exports the
dashboard data, and publishes `population.db` + `docs/population.json` to `main`.
it never hardcodes connection details - they come from repository secrets:

| secret | required | example |
| --- | --- | --- |
| `DA_HOST` | yes | `chaotic-minds.dynu.net` |
| `DA_PORT` | yes | `6900` |
| `DA_NAME` | yes | your character name |
| `DA_PASSWORD` | yes | your account password |
| `DA_CLIENT_VERSION` | no | pin the handshake version; leave unset to auto-read it from the patch server each run (see [client version](#client-version)) |

set them under **Settings → Secrets and variables → Actions**. the workflow needs
`contents: write` (already declared) so it can push the updated database. you can
also trigger it manually from the Actions tab (`Run workflow`).

**history is not kept.** to stop the repo bloating from an hourly binary commit
forever, each run rewrites `main` as a single root commit (code + latest data) and
force-pushes it. the database still holds every row - only git history is
discarded. consequence: `main` is force-pushed, so a local clone can't `git pull`;
re-sync with `git fetch && git reset --hard origin/main`, and don't expect commit
history to persist. (`--force-with-lease` still refuses to clobber a manual push
that lands mid-run; that run fails and the next hour recovers.)

## dashboard

`docs/index.html` is a self-contained page (no external dependencies) that fetches
`docs/population.json` and charts total players online (with the active, non-AFK
count overlaid) and the per-class breakdown over time, with a range selector, class
toggles, hover readouts, and light/dark themes. times are shown in the viewer's
local zone (labelled on the page). failed hours show as gaps.

the exported json stays small no matter how long the tracker runs: it is written
compact (no whitespace), and only the last `--recent-days` (default 90) are kept at
full hourly resolution - older data is rolled up to one averaged point per day. the
database keeps every raw row, so you can always re-export at a different window or
query the raw history directly.

to publish it on **GitHub Pages**: Settings → Pages → Source = *Deploy from a
branch*, branch = `main`, folder = `/docs`. the page will be served at
`https://<user>.github.io/<repo>/` and refresh itself each hour as the action
commits new data.

to preview locally (a plain `file://` open is blocked from fetching the json):

```sh
cd docs && py -3.14 -m http.server 8000   # then open http://localhost:8000
```

regenerate the json by hand after local runs with:

```sh
py -3.14 -m population_tracker.export --database population.db --output docs/population.json
```

example query - hourly peak:

```sql
SELECT substr(recorded_at, 1, 13) AS hour, MAX(total) AS peak
FROM population
GROUP BY hour
ORDER BY hour;
```

## how it works

the connection walks the standard lifecycle, driven by
[`client.py`](src/population_tracker/client.py):

1. **lobby** - connect, send the version, receive crypto parameters, request the
   server table, select a server.
2. **login** - follow the redirect, send credentials, receive the world redirect.
3. **world** - follow the redirect, wait for world entry, request the country
   list once, then send a logout and disconnect.

the world server would drop clients that miss more than two heartbeats, so the
client answers every heartbeat and tick-sync request during its brief stay.

modules:

- `crypto.py` - the three-mode packet cipher and key derivation
- `protocol.py` - framing, field readers/writers, and packet bodies
- `client.py` - the async connection state machine
- `version_resolver.py` - reads the live client version off the patch server
- `storage.py` - the sqlite `population` table
- `tables.py` - generated protocol constant tables (salt + crc)

## client version

the lobby handshake rejects a mismatched version, so the tracker must report
whatever the live client ships. it works this out on its own - there is nothing
to bump when the client updates.

when `--client-version` / `DA_CLIENT_VERSION` is not set,
[`version_resolver.py`](src/population_tracker/version_resolver.py) reads the
version from the same patch server the official launcher uses
(`http://unora.freeddns.org:5001/api/files/`, taken from the decompiled launcher):

1. `GET Unora/details` - a small JSON listing with each file's hash. If the
   `Chaos.Client.dll` hash matches a value already in `.client-version-cache.json`
   (next to the database), the cached version is used and nothing is downloaded.
2. On a new hash, `GET Unora/get/ChaosClient/Chaos.Client.dll` fetches the DLL and
   the version is read out of it, then cached against that hash.

the version is the `GlobalSettings.ClientVersion` constant - a compile-time
`ushort`. a constant getter compiles to the IL `ldc.i4 <n>; ret`, so the resolver
scans the DLL bytes for that instruction and takes the one value in the plausible
range (`700`-`999`); if it finds zero or several it declines rather than guess.
this keeps the tracker a pure-python, zero-.NET dependency at runtime.

any failure (server down, ambiguous parse) falls back to `CLIENT_VERSION_FALLBACK`
in `version_resolver.py`, so a flaky server never blocks a sample. keep that
constant roughly current as the offline safety net. to pin a specific version and
skip the lookup entirely, pass `--client-version N` or set `DA_CLIENT_VERSION`.

do **not** read the version from the Chaos.Client source repo - it lags the
shipped build (it said `741` while the client shipped `745`). for a one-off manual
check against a local install, [`get_client_version.py`](tools/get_client_version.py)
decompiles the constant with `ilspycmd` (install: `dotnet tool install -g ilspycmd`):

```sh
py tools/get_client_version.py [path/to/Chaos.Client.dll]   # defaults to the Unora install
```

## validating the crypto

`tables.py` is generated from the `Chaos.Cryptography` source:

```sh
py tools/generate_tables.py [path/to/Chaos-Server/Chaos.Cryptography/Tables.cs]
```

the hand-ported cipher is checked byte-for-byte against the real libraries in all
four directions (client/server x encrypt/decrypt), plus a full login round-trip
that confirms the server would accept the produced login packet:

```sh
dotnet build -c Release tools/CryptoVectors
py tools/validate_crypto.py
```

## tests

```sh
py -3.14 -m pytest
```

covers framing, server-table and country-list parsing, the login integrity block,
sqlite persistence, and a full lifecycle test (lobby -> login -> world -> read ->
logout) against an in-process mock server that speaks the real protocol.
