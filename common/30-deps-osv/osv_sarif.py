"""Runs OSV-Scanner on /scan/repo and prints SARIF 2.1.0.

Two modes:

  lockfiles   The lock files, with the local database at /data. No network.
              pom.xml is left to the mode "maven".
  maven       The pom.xml files, with their versions resolved through the
              Maven registry that --registry gives (the proxy of the stage),
              and the local database at /data.

OSV-Scanner ends with code 1 when it finds a flaw and with code 128 when the
repository has no lock file. Its SARIF has no mark for the internal
packages. So this program reads its JSON and writes the SARIF itself. In the
mode "maven", it also lists the internal packages that the pom.xml files
name, also in a profile: the resolver does not read the profiles.

Exit code: 0 with a SARIF, or 2 when OSV-Scanner fails or cannot read a
file. A failure blocks the scan: the runner does not see what was missed.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

REPO = "/scan/repo"
# Our settings, empty: the settings of the target (osv-scanner.toml) are
# never read.
CONFIG = "/opt/ci-scan/osv-scanner.toml"

FOUND = 1
NO_PACKAGES = 128

# Signs in the error output that a file was not fully read.
BROKEN = ("Error during extraction", "failed resolution")


def command(mode, registry=None):
    args = [
        "osv-scanner", "scan", "source",
        "--recursive",
        "--no-ignore",
        "--config", CONFIG,
        "--all-packages",
        "--format", "json",
    ]
    if mode == "lockfiles":
        args += ["--offline", "--x-disable-plugins", "java/pomxml"]
    else:
        args += [
            "--offline-vulnerabilities",
            "--data-source", "native",
            "--maven-registry", registry,
        ]
    return args + [REPO]


def main_id(ids):
    """The id that names a group of aliases: a malicious package first,
    then a CVE, then the first id."""
    for prefix in ("MAL-", "CVE-"):
        for id_ in sorted(ids):
            if id_.startswith(prefix):
                return id_
    return sorted(ids)[0]


def severity(ids, max_severity):
    if any(id_.startswith("MAL-") for id_ in ids):
        return "Critical"
    return max_severity or None


def is_internal(name, internal):
    """A Maven name is group:artifact. The prefix applies to the group."""
    group = name.split(":")[0]
    return any(group == prefix.rstrip(".") or group.startswith(prefix) for prefix in internal)


def local(tag):
    return tag.rsplit("}", 1)[-1]


def child(element, name):
    for item in element:
        if local(item.tag) == name:
            return (item.text or "").strip()
    return ""


def internal_in_poms(root, internal):
    """The internal dependencies written in the pom.xml files, also in the
    profiles, which the resolver does not read: [(path, name, version)].
    A version ${name} takes the value of the property of the same file."""
    found = []
    for folder, _, names in sorted(os.walk(root)):
        if "pom.xml" not in names:
            continue
        path = os.path.join(folder, "pom.xml")
        try:
            project = ET.parse(path).getroot()
        except ET.ParseError:
            continue
        values = {"project.version": child(project, "version")}
        for element in project:
            if local(element.tag) == "properties":
                values.update({local(item.tag): (item.text or "").strip() for item in element})

        def expand(text):
            return re.sub(r"\$\{([^}]+)\}", lambda match: values.get(match.group(1), match.group(0)), text)

        for element in project.iter():
            if local(element.tag) != "dependency":
                continue
            name = f"{child(element, 'groupId')}:{child(element, 'artifactId')}"
            if is_internal(name, internal):
                found.append((path, name, expand(child(element, "version"))))
    return found


def internal_note(name, version, uri):
    return {
        "ruleId": "internal-package",
        "kind": "informational",
        "level": "none",
        "message": {"text": f"Paquet interne, non vérifié ici : {name}@{version}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
    }


def convert(report, internal=()):
    rules = {}
    results = []
    for source in report.get("results") or []:
        uri = source.get("source", {}).get("path", "")
        location = [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]
        for entry in source.get("packages") or []:
            package = entry.get("package", {})
            name = package.get("name", "?")
            version = package.get("version", "")
            if internal and is_internal(name, internal):
                results.append(internal_note(name, version, uri))
                continue
            summaries = {v.get("id"): v.get("summary") or v.get("details", "")[:200]
                         for v in entry.get("vulnerabilities") or []}
            for group in entry.get("groups") or []:
                # "ids": the entries of the database; "aliases": the same
                # flaw under other names, often its CVE.
                ids = sorted(set(group.get("ids") or []) | set(group.get("aliases") or []))
                if not ids:
                    continue
                main = main_id(ids)
                rule_id = f"{name}@{version} {main}"
                summary = next((summaries[i] for i in ids if summaries.get(i)), "")
                if rule_id not in rules:
                    rule = {
                        "id": rule_id,
                        "shortDescription": {"text": f"{main}: {summary}".strip()},
                        "helpUri": f"https://osv.dev/vulnerability/{main}",
                    }
                    score = severity(ids, group.get("max_severity"))
                    if score:
                        rule["properties"] = {"security-severity": score}
                    rules[rule_id] = rule
                others = sorted(set(ids) - {main})
                text = f"{name}@{version} : {main}"
                if others:
                    text += f" ({', '.join(others)})"
                if summary:
                    text += f" — {summary}"
                results.append({
                    "ruleId": rule_id,
                    "level": "error",
                    "message": {"text": text},
                    "locations": location,
                })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "osv-scanner",
                "informationUri": "https://google.github.io/osv-scanner/",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def scan(args, run=subprocess.run, repo=REPO):
    """Gives (exit code, SARIF text or None, error text)."""
    done = run(command(args.mode, args.registry), capture_output=True, text=True)
    # No lock file: nothing to check. OSV-Scanner then also complains that
    # it has no database, which does not matter.
    if done.returncode == NO_PACKAGES:
        return 0, json.dumps(convert({})), ""
    broken = next((line for line in done.stderr.splitlines() if any(sign in line for sign in BROKEN)), None)
    if broken:
        return 2, None, broken
    if done.returncode not in (0, FOUND):
        return 2, None, done.stderr.strip() or f"osv-scanner: code {done.returncode}"
    try:
        report = json.loads(done.stdout)
    except ValueError as error:
        return 2, None, f"osv-scanner: JSON illisible ({error})"
    sarif = convert(report, args.internal)
    if args.mode == "maven" and args.internal:
        results = sarif["runs"][0]["results"]
        listed = {result["message"]["text"] for result in results if result.get("kind") == "informational"}
        for path, name, version in internal_in_poms(repo, args.internal):
            note = internal_note(name, version, path)
            if note["message"]["text"] not in listed:
                listed.add(note["message"]["text"])
                results.append(note)
    return 0, json.dumps(sarif), ""


def parse(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["lockfiles", "maven"])
    parser.add_argument("--registry", help="the Maven registry (mode maven)")
    parser.add_argument("--internal", action="append", default=[],
                        help="a group prefix of internal packages, for example ch.vs.")
    args = parser.parse_args(argv)
    if args.mode == "maven" and not args.registry:
        parser.error("the mode maven needs --registry")
    return args


def main():
    code, sarif, error = scan(parse(sys.argv[1:]))
    if error:
        print(error, file=sys.stderr)
    if sarif:
        print(sarif)
    return code


if __name__ == "__main__":
    sys.exit(main())
