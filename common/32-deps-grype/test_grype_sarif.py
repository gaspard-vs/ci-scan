"""Tests of grype_sarif.py. They run in the image of the stage, from npm test."""

import json
import os
import tempfile
import unittest
from types import SimpleNamespace

import grype_sarif

SBOM = {
    "bomFormat": "CycloneDX",
    "components": [
        {"type": "library", "name": "commons-text", "version": "1.9",
         "purl": "pkg:maven/org.apache.commons/commons-text@1.9"},
        {"type": "file", "name": "/lib/commons-text-1.9.jar"},
    ],
}


def match(id_, severity, name, version, purl, paths, related=(), description="A flaw."):
    return {
        "vulnerability": {"id": id_, "severity": severity, "description": description,
                          "dataSource": f"https://github.com/advisories/{id_}"},
        "relatedVulnerabilities": [{"id": item} for item in related],
        "artifact": {"name": name, "version": version, "purl": purl,
                     "locations": [{"path": path} for path in paths]},
    }


TEXT4SHELL = match("GHSA-599f-7c49-w659", "Critical", "commons-text", "1.9",
                   "pkg:maven/org.apache.commons/commons-text@1.9", ["/lib/commons-text-1.9.jar"],
                   ["CVE-2022-42889"], "Arbitrary code execution in Apache Commons Text\nMore text.")
REPORT = {"descriptor": {"name": "grype", "version": "0.121.1"}, "matches": [TEXT4SHELL]}


def fake(code=0, stdout="", stderr=""):
    seen = []

    def run(args, **options):
        seen.append((args, options))
        return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)

    return run, seen


def sbom_file(content):
    folder = tempfile.mkdtemp()
    path = os.path.join(folder, "sbom.cdx.json")
    with open(path, "w", encoding="utf-8") as file:
        file.write(content if isinstance(content, str) else json.dumps(content))
    return path


class Convert(unittest.TestCase):
    def test_a_flaw_is_named_by_its_cve_and_by_the_maven_name_of_osv(self):
        [run] = grype_sarif.convert(REPORT)["runs"]
        [result] = run["results"]
        self.assertEqual(result["ruleId"], "org.apache.commons:commons-text@1.9 CVE-2022-42889")
        self.assertEqual(result["message"]["text"],
                         "org.apache.commons:commons-text@1.9 : CVE-2022-42889 (GHSA-599f-7c49-w659)"
                         " — Arbitrary code execution in Apache Commons Text")
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                         "lib/commons-text-1.9.jar")
        [rule] = run["tool"]["driver"]["rules"]
        self.assertEqual(rule["properties"], {"security-severity": "critical"})
        self.assertEqual(rule["helpUri"], "https://github.com/advisories/GHSA-599f-7c49-w659")
        self.assertEqual(run["tool"]["driver"]["version"], "0.121.1")

    def test_an_npm_package_keeps_its_name(self):
        scoped = match("GHSA-x", "High", "@angular/router", "20.0.0", "pkg:npm/%40angular/router@20.0.0",
                       ["/ui/package-lock.json"])
        [result] = grype_sarif.convert({"matches": [scoped]})["runs"][0]["results"]
        self.assertEqual(result["ruleId"], "@angular/router@20.0.0 GHSA-x")

    def test_negligible_is_low_and_unknown_takes_the_gravity_of_the_stage(self):
        report = {"matches": [
            match("CVE-1", "Negligible", "a", "1", "pkg:npm/a@1", ["/package-lock.json"]),
            match("CVE-2", "Unknown", "b", "1", "pkg:npm/b@1", ["/package-lock.json"]),
        ]}
        rules = grype_sarif.convert(report)["runs"][0]["tool"]["driver"]["rules"]
        self.assertEqual(rules[0]["properties"], {"security-severity": "low"})
        self.assertNotIn("properties", rules[1])

    def test_one_result_for_each_file_and_no_double(self):
        twice = match("CVE-1", "High", "a", "1", "pkg:npm/a@1", ["/x/package-lock.json", "/y/package-lock.json"])
        results = grype_sarif.convert({"matches": [twice, twice]})["runs"][0]["results"]
        uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results]
        self.assertEqual(uris, ["x/package-lock.json", "y/package-lock.json"])

    def test_no_match_gives_no_result(self):
        self.assertEqual(grype_sarif.convert({})["runs"][0]["results"], [])


class Scan(unittest.TestCase):
    def test_grype_reads_the_sbom_with_our_settings_from_tmp(self):
        run, seen = fake(stdout=json.dumps(REPORT))
        path = sbom_file(SBOM)
        code, sarif, error = grype_sarif.scan(run, sbom_path=path)
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(len(json.loads(sarif)["runs"][0]["results"]), 1)
        [(args, options)] = seen
        self.assertEqual(args, ["grype", f"sbom:{path}", "--config", "/opt/ci-scan/grype.yaml",
                                "--output", "json", "--quiet"])
        self.assertEqual(options["cwd"], "/tmp")
        self.assertEqual(options["env"]["GRYPE_DB_CACHE_DIR"], "/data/grype-db")

    def test_an_sbom_with_no_component_needs_no_grype(self):
        run, seen = fake()
        code, sarif, _ = grype_sarif.scan(run, sbom_path=sbom_file({"bomFormat": "CycloneDX", "components": [
            {"type": "file", "name": "/README.md"}]}))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(sarif)["runs"][0]["results"], [])
        self.assertEqual(seen, [])

    def test_an_sbom_that_cannot_be_read_fails_the_stage(self):
        run, _ = fake()
        code, sarif, error = grype_sarif.scan(run, sbom_path=sbom_file("nothing"))
        self.assertEqual((code, sarif), (2, None))
        self.assertIn("SBOM illisible", error)
        code, _, _ = grype_sarif.scan(run, sbom_path="/no/such/file")
        self.assertEqual(code, 2)

    def test_a_failure_of_grype_fails_the_stage(self):
        run, _ = fake(code=1, stderr="failed to load vulnerability db\n")
        self.assertEqual(grype_sarif.scan(run, sbom_path=sbom_file(SBOM)),
                         (2, None, "grype: code 1: failed to load vulnerability db"))

    def test_a_result_that_is_not_a_report_fails_the_stage(self):
        for stdout in ("nothing", json.dumps({"other": 1})):
            run, _ = fake(stdout=stdout)
            code, sarif, _ = grype_sarif.scan(run, sbom_path=sbom_file(SBOM))
            self.assertEqual((code, sarif), (2, None))


class Prepare(unittest.TestCase):
    def test_the_archive_is_imported_into_the_folder_to_prepare(self):
        run, seen = fake()
        self.assertEqual(grype_sarif.prepare(run), (0, None, ""))
        [(args, options)] = seen
        self.assertEqual(args, ["grype", "db", "import", "/data/grype/vulnerability-db.tar.zst",
                                "--config", "/opt/ci-scan/grype.yaml"])
        self.assertEqual(options["env"]["GRYPE_DB_CACHE_DIR"], "/prepare")

    def test_a_failure_of_the_import_fails_the_preparation(self):
        run, _ = fake(code=1, stderr="bad archive\n")
        self.assertEqual(grype_sarif.prepare(run), (2, None, "grype db import: code 1: bad archive"))


class Main(unittest.TestCase):
    def test_an_unknown_mode_fails(self):
        self.assertEqual(grype_sarif.main(["other"]), 2)


if __name__ == "__main__":
    unittest.main()
