"""Tests of sbom_sarif.py. They run in the image of the stage, from npm test."""

import json
import unittest
from types import SimpleNamespace

import sbom_sarif

SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "metadata": {"tools": {"components": [{"type": "application", "name": "syft", "version": "1.57.2"}]}},
    "components": [
        {"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
        {"type": "library", "name": "commons-text", "version": "1.9",
         "purl": "pkg:maven/org.apache.commons/commons-text@1.9"},
        {"type": "file", "name": "/package-lock.json"},
    ],
}


def fake(code=0, stdout="", stderr=""):
    seen = []

    def run(args, **options):
        seen.append((args, options))
        return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)

    return run, seen


class Convert(unittest.TestCase):
    def test_the_sbom_is_the_output_and_there_is_no_result(self):
        [run] = sbom_sarif.convert(SBOM)["runs"]
        self.assertEqual(run["results"], [])
        self.assertEqual(run["properties"]["ci-scan/output"], {"name": "sbom.cdx.json", "content": SBOM})
        self.assertEqual(run["tool"]["driver"]["version"], "1.57.2")

    def test_the_summary_counts_the_components_without_the_files(self):
        self.assertEqual(sbom_sarif.summary(SBOM), "2 composants")
        self.assertEqual(sbom_sarif.summary({"components": [SBOM["components"][0]]}), "1 composant")
        self.assertEqual(sbom_sarif.summary({}), "0 composant")


class Scan(unittest.TestCase):
    def test_syft_reads_our_settings_from_tmp(self):
        run, seen = fake(stdout=json.dumps(SBOM))
        code, sarif, error = sbom_sarif.scan(run)
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(json.loads(sarif)["version"], "2.1.0")
        [(args, options)] = seen
        self.assertEqual(args, ["syft", "scan", "dir:/scan/repo", "--config", "/opt/ci-scan/syft.yaml",
                                "--output", "cyclonedx-json@1.6", "--quiet"])
        self.assertEqual(options["cwd"], "/tmp")

    def test_a_failure_of_syft_fails_the_stage(self):
        run, _ = fake(code=1, stderr="cannot read\n")
        self.assertEqual(sbom_sarif.scan(run), (2, "", "syft: code 1: cannot read"))

    def test_an_sbom_that_is_not_json_fails_the_stage(self):
        run, _ = fake(stdout="nothing")
        code, sarif, error = sbom_sarif.scan(run)
        self.assertEqual((code, sarif), (2, ""))
        self.assertIn("not JSON", error)

    def test_an_sbom_that_is_not_cyclonedx_fails_the_stage(self):
        run, _ = fake(stdout=json.dumps({"spdxVersion": "SPDX-2.3"}))
        self.assertEqual(sbom_sarif.scan(run), (2, "", "syft: the SBOM is not CycloneDX"))


if __name__ == "__main__":
    unittest.main()
