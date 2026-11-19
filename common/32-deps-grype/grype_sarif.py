"""Runs Grype on the SBOM of the Syft stage and prints SARIF 2.1.0.

Two modes:

  prepare   Once a day, before the first scan. Imports the database archive
            (/data, read-only) into /prepare, the only folder where the stage
            can write. `grype db import` adds indexes and writes the
            checksum that Grype checks at each start. It takes about 40 s.
  scan      Reads the SBOM at /input and the prepared database at /data,
            both read-only. No network.

Grype never reads the target: only the SBOM, with our settings (--config),
started in /tmp. A .grype.yaml of the target has no effect.

The name of a package is the one of OSV-Scanner (group:artifact for Maven),
and a flaw is named by its CVE when it has one: the two stages give the
same names in the report.

Exit code: 0 with a SARIF (or a prepared database), or 2 when Grype fails or
gives a result that cannot be read. A failure blocks the scan.
"""

import json
import os
import subprocess
import sys
from urllib.parse import unquote

SBOM = "/input/sbom.cdx.json"
CONFIG = "/opt/ci-scan/grype.yaml"
# The archive that the runner downloads, and the folder of the prepared
# database, both in the data of the day.
ARCHIVE = "/data/grype/vulnerability-db.tar.zst"
PREPARED = "/data/grype-db"
PREPARE = "/prepare"

# The words of Grype that the runner does not know. "Unknown" gives no
# word: the gravity of the stage applies.
SEVERITIES = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "negligible": "low"}


def environment(db):
    return {**os.environ, "GRYPE_DB_CACHE_DIR": db}


def components(sbom):
    """The components of the SBOM, files excluded."""
    return [item for item in sbom.get("components") or [] if item.get("type") != "file"]


def package_name(artifact):
    """group:artifact for Maven, else the name that Grype gives."""
    purl = artifact.get("purl") or ""
    if purl.startswith("pkg:maven/"):
        path = purl[len("pkg:maven/"):].split("@")[0].split("?")[0]
        parts = [unquote(part) for part in path.split("/")]
        if len(parts) == 2:
            return f"{parts[0]}:{parts[1]}"
    return artifact.get("name") or "?"


def flaw_ids(match):
    """The id of the flaw and its aliases: the CVE first, then the rest."""
    main = match.get("vulnerability", {}).get("id") or "?"
    related = {item.get("id") for item in match.get("relatedVulnerabilities") or []} - {None, main}
    cves = sorted(id_ for id_ in related | {main} if id_.startswith("CVE-"))
    first = cves[0] if cves else main
    return first, sorted((related | {main}) - {first})


def uris(artifact):
    """The files of the target where the package is written, from the root
    of the target."""
    found = []
    for location in artifact.get("locations") or []:
        path = (location.get("path") or "").lstrip("/")
        if path and path not in found:
            found.append(path)
    return found or [""]


def convert(report):
    rules = {}
    results = []
    seen = set()
    for match in report.get("matches") or []:
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        name = package_name(artifact)
        version = artifact.get("version", "")
        main, others = flaw_ids(match)
        rule_id = f"{name}@{version} {main}"
        summary = (vulnerability.get("description") or "").strip().split("\n")[0][:200]
        if rule_id not in rules:
            rule = {"id": rule_id, "shortDescription": {"text": f"{main}: {summary}".strip()}}
            if vulnerability.get("dataSource"):
                rule["helpUri"] = vulnerability["dataSource"]
            severity = SEVERITIES.get((vulnerability.get("severity") or "").lower())
            if severity:
                rule["properties"] = {"security-severity": severity}
            rules[rule_id] = rule
        text = f"{name}@{version} : {main}"
        if others:
            text += f" ({', '.join(others)})"
        if summary:
            text += f" — {summary}"
        for uri in uris(artifact):
            if (rule_id, uri) in seen:
                continue
            seen.add((rule_id, uri))
            result = {"ruleId": rule_id, "level": "error", "message": {"text": text}}
            if uri:
                result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]
            results.append(result)
    driver = {"name": "grype", "informationUri": "https://github.com/anchore/grype", "rules": list(rules.values())}
    version = (report.get("descriptor") or {}).get("version")
    if version:
        driver["version"] = version
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }


def scan(run=subprocess.run, sbom_path=SBOM, db=PREPARED):
    """Gives (exit code, SARIF text or None, error text)."""
    try:
        with open(sbom_path, encoding="utf-8") as file:
            sbom = json.load(file)
    except (OSError, ValueError) as error:
        return 2, None, f"SBOM illisible ({error})"
    # No component: nothing to check, and no need of the database.
    if not components(sbom):
        return 0, json.dumps(convert({})), ""
    command = ["grype", f"sbom:{sbom_path}", "--config", CONFIG, "--output", "json", "--quiet"]
    done = run(command, cwd="/tmp", env=environment(db), capture_output=True, text=True)
    if done.returncode != 0:
        return 2, None, f"grype: code {done.returncode}: {done.stderr.strip()}"
    try:
        report = json.loads(done.stdout)
    except ValueError as error:
        return 2, None, f"grype: JSON illisible ({error})"
    if not isinstance(report, dict) or not isinstance(report.get("matches"), list):
        return 2, None, "grype: no list of matches"
    return 0, json.dumps(convert(report)), ""


def prepare(run=subprocess.run, archive=ARCHIVE, target=PREPARE):
    """Gives (exit code, None, error text)."""
    done = run(["grype", "db", "import", archive, "--config", CONFIG],
               cwd="/tmp", env=environment(target), capture_output=True, text=True)
    if done.returncode != 0:
        return 2, None, f"grype db import: code {done.returncode}: {done.stderr.strip()}"
    return 0, None, ""


def main(argv):
    if argv != ["scan"] and argv != ["prepare"]:
        print("usage: grype_sarif.py scan|prepare", file=sys.stderr)
        return 2
    code, sarif, error = scan() if argv == ["scan"] else prepare()
    if error:
        print(error, file=sys.stderr)
    if sarif:
        print(sarif)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
