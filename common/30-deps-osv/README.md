# OSV stage

OSV-Scanner finds the packages with a known flaw, and the malicious
packages, in the lock files of the target. It has no network: it reads a
local copy of the OSV database.

| Path | Content |
| --- | --- |
| `Dockerfile` | The image: Python and OSV-Scanner, both by digest. The Maven stage (`../31-deps-maven`) uses the same image. |
| `osv_sarif.py` | Runs OSV-Scanner, reads its JSON and writes the SARIF. Python standard library only. |
| `test_osv_sarif.py` | Its tests. `npm test` runs them in the image. |
| `osv-scanner.toml` | Our settings: none. They replace the settings of the target. |
| `stage.json` | The stage, and the database of each ecosystem with the file names that need it. |

## The database

The runner downloads only the databases that the target needs (a
`package-lock.json` needs npm). It keeps them in `~/.cache/ci-scan/data/<day>/`
(or `$CI_SCAN_CACHE`). Before each scan, it asks OSV for the MD5 of each file
(`HEAD`) and uses the cached file only if it is the same. A cache is not
trusted: on GitHub, a workflow of the target can write it.

A lock file of an ecosystem with no database makes OSV-Scanner fail: the
stage blocks.

## Why our own SARIF

- OSV-Scanner ends with code 1 when it finds a flaw, and with code 128, with
  no output, when the target has no lock file. The stage contract wants
  code 0 and a SARIF.
- A malicious package (`MAL-…`) must be critical. OSV gives it no score.
- The Maven stage lists the internal packages for information.

The rule of a result is `<package>@<version> <flaw>`: the CVE when the flaw
has one. A flaw with no score takes the gravity of the stage: high.

## The target cannot silence a flaw

- `--config` with our empty settings: the `osv-scanner.toml` of the target
  is not read.
- `--no-ignore`: a lock file in `.gitignore` is still read.
