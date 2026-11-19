# Grype stage

Grype is the second opinion on known flaws. It reads the SBOM that the
Syft stage gives (`sbom.cdx.json`) and compares it with the Grype database.
It never reads the target. It has no network.

| Path | Content |
| --- | --- |
| `Dockerfile` | The image: Python and Grype, both by digest. The Python base is the one of the OSV image. |
| `grype_sarif.py` | Prepares the database (`prepare`), or runs Grype and writes the SARIF (`scan`). Python standard library only. |
| `test_grype_sarif.py` | Its tests. `npm test` runs them in the image. |
| `grype.yaml` | Our settings: no update, no ignore rule, no VEX. |
| `stage.json` | The stage. |

## The input

`"input": "sbom.cdx.json"`: the runner gives the SBOM of the Syft stage at
`/input`, read-only. If Syft failed, the file is missing: the Grype stage
does not run, and the scan blocks.

An SBOM with no component needs no check: Grype does not start.

## The database

| Step | Where | Time here |
| --- | --- | --- |
| The runner reads `latest.json` of Grype: the name of the archive, its sha256, its date | Runner | < 1 s |
| The runner downloads the archive (204 MB) and checks its sha256. The cache of the day keeps it | Runner | 3 s |
| `grype_sarif.py prepare`: `grype db import`, into `grype-db/` of the day. Grype adds indexes (3.5 GB) and writes the checksum that it checks at each start | Image of the stage, once a day, no target, no network | 60 s |
| `grype_sarif.py scan` reads `grype-db/` at `/data`, read-only | Image of the stage, each scan | 3 s |

The runner prepares the folder again when the archive or the image changes
(the mark `grype-db.ready`). A failed preparation leaves no folder, and
blocks the scan.

Not kept: the import at each scan, in `/tmp`. It takes 40 s and 3.5 GB of
memory for each scan. Unpacking the archive alone is not enough: Grype
refuses a database that it did not import.

On GitHub, each scan starts on a new machine: download and preparation each
time, about 1 minute.

Grype refuses a database older than 5 days (our setting, the default).

## The names

A result has the name of OSV-Scanner: `<package>@<version> <flaw>`, with
`group:artifact` for Maven and the CVE when the flaw has one. So the report
shows the same flaw with the same name under both tools.

| Grype severity | Gravity |
| --- | --- |
| Critical, High, Medium, Low | the same |
| Negligible | low |
| Unknown | the gravity of the stage: high |

## The target cannot hide a flaw

Grype starts in `/tmp` with `--config` and our settings. It does not see the
target. The fixture `grype-silenced` has a `.grype.yaml` that ignores
lodash: the stage still finds it.

## Compared with OSV-Scanner

- Grype sees a library delivered as a `.jar` file (fixture `sbom-jar`:
  commons-text 1.9, CVE-2022-42889). OSV-Scanner does not.
- Maven: Grype sees only the dependencies that the SBOM lists, the ones
  written in `pom.xml`. OSV-Scanner also checks the dependencies of the
  dependencies.
- The internal packages (`ch.vs.*`) are listed for information by the OSV
  Maven stage only.
