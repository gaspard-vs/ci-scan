# Syft stage

Syft makes the inventory of the components of the target: the SBOM, in
CycloneDX 1.6 JSON. Its only way out is the Maven helper of
`../31-deps-maven`, for the versions that a parent POM gives. The stage
finds nothing and never blocks, except when Syft fails: the inventory is
then missing.

| Path | Content |
| --- | --- |
| `Dockerfile` | The image: Python and Syft, both by digest. The Python base is the one of the OSV image. |
| `sbom_sarif.py` | Runs Syft and writes a SARIF with no result, which holds the SBOM. Python standard library only. |
| `test_sbom_sarif.py` | Its tests. `npm test` runs them in the image. |
| `syft.yaml` | Our settings. They replace the settings of the target. |
| `stage.json` | The stage. |

## How the SBOM leaves

The container writes nowhere. `sbom_sarif.py` prints a SARIF run with two
properties:

- `ci-scan/output`: `{"name": "sbom.cdx.json", "content": <the SBOM>}`. The
  runner writes the file in the `--out` folder, next to `ci-scan.sarif`, and
  removes it from the SARIF of the scan.
- `ci-scan/summary`: the number of components, for the report.

On GitHub, `scan.yml` keeps the `--out` folder as the artifact `ci-scan` of
the run.

## The target cannot hide a component

Syft reads `.syft.yaml` from the current folder. `sbom_sarif.py` starts it in
`/tmp`, with `--config` and our settings. The fixture `sbom-silenced` has a
`.syft.yaml` that excludes its files: Syft started in the target lists
nothing, and the stage lists all.

## What Syft reads

- The lock files and the manifests (`package-lock.json`, `pom.xml`, …).
- The `.jar` files: a library delivered as a file (fixture `sbom-jar`).
  OSV-Scanner does not see it.

Our settings drop the components of type "file": the SBOM lists packages
only.

## Maven versions

A Quarkus or Spring project writes almost no version in `pom.xml`: the
parent or a BOM gives it. Without network, 22 of the 35 components of
`bpesvc` had no version. So Syft asks the POM files through the helper of
the OSV Maven stage, with the same arguments (a test checks it): `GET` of
POM files to Maven Central only, `ch.vs.*` never sent, each request in the
report. `bpesvc`: 69 requests, 8 s, all versions known.

| Setting for `bpesvc` | Components | Version unknown | Time | Requests |
| --- | --- | --- | --- | --- |
| No network | 35 | 22 | 1 s | 0 |
| Parent versions (kept) | 35 | 0 | 8 s | 69 |
| Also the dependencies of the dependencies | — | — | > 10 min | > 6900 |

## Limits

- Maven: only the dependencies written in `pom.xml`, not the dependencies
  of the dependencies. OSV-Scanner checks them through the helper. Later,
  the list that the OSV Maven stage resolved can complete the SBOM.
- The name of the component of the SBOM is `/scan/repo`. The central store,
  later, gives the name of the repository.
