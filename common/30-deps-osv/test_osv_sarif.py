"""Tests of osv_sarif.py. They run in the image of the stage, from npm test."""

import json
import os
import tempfile
import unittest
from argparse import Namespace
from types import SimpleNamespace

import osv_sarif


def package(name, version, groups=(), vulnerabilities=()):
    return {
        "package": {"name": name, "version": version},
        "groups": list(groups),
        "vulnerabilities": list(vulnerabilities),
    }


def report(*packages, path="/scan/repo/package-lock.json"):
    return {"results": [{"source": {"path": path}, "packages": list(packages)}]}


LODASH = package(
    "lodash", "4.17.15",
    groups=[{"ids": ["GHSA-p6mc-m468-83gw"], "aliases": ["CVE-2020-8203", "GHSA-p6mc-m468-83gw"],
             "max_severity": "7.4"}],
    vulnerabilities=[{"id": "GHSA-p6mc-m468-83gw", "summary": "Prototype pollution"}],
)


def run_of(sarif):
    return sarif["runs"][0]


class Convert(unittest.TestCase):
    def test_a_flaw_gives_one_rule_and_one_result(self):
        run = run_of(osv_sarif.convert(report(LODASH)))
        [rule] = run["tool"]["driver"]["rules"]
        self.assertEqual(rule["id"], "lodash@4.17.15 CVE-2020-8203")
        self.assertEqual(rule["properties"]["security-severity"], "7.4")
        [result] = run["results"]
        self.assertEqual(result["ruleId"], rule["id"])
        self.assertEqual(result["message"]["text"],
                         "lodash@4.17.15 : CVE-2020-8203 (GHSA-p6mc-m468-83gw) — Prototype pollution")
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                         "/scan/repo/package-lock.json")

    def test_a_malicious_package_is_critical(self):
        bad = package("flatmap-stream", "0.1.1", groups=[{"ids": ["MAL-2025-20690"], "max_severity": ""}])
        [rule] = run_of(osv_sarif.convert(report(bad)))["tool"]["driver"]["rules"]
        self.assertEqual(rule["id"], "flatmap-stream@0.1.1 MAL-2025-20690")
        self.assertEqual(rule["properties"]["security-severity"], "Critical")

    def test_a_flaw_with_no_score_has_no_severity(self):
        loose = package("left-pad", "1.0.0", groups=[{"ids": ["GHSA-xxxx"], "max_severity": ""}])
        [rule] = run_of(osv_sarif.convert(report(loose)))["tool"]["driver"]["rules"]
        self.assertNotIn("properties", rule)

    def test_a_package_with_no_flaw_gives_nothing(self):
        run = run_of(osv_sarif.convert(report(package("is-number", "7.0.0"))))
        self.assertEqual(run["results"], [])

    def test_an_internal_package_is_for_information(self):
        internal = package("ch.vs.sci:java-quarkus", "2.1")
        public = package("org.yaml:snakeyaml", "1.28")
        run = run_of(osv_sarif.convert(report(internal, public, path="/scan/repo/pom.xml"), ["ch.vs."]))
        [result] = run["results"]
        self.assertEqual(result["kind"], "informational")
        self.assertEqual(result["message"]["text"], "Paquet interne, non vérifié ici : ch.vs.sci:java-quarkus@2.1")

    def test_the_prefix_is_a_whole_group_name(self):
        self.assertTrue(osv_sarif.is_internal("ch.vs:core", ["ch.vs."]))
        self.assertFalse(osv_sarif.is_internal("ch.vsx:core", ["ch.vs."]))

    def test_no_result_gives_an_empty_run(self):
        self.assertEqual(run_of(osv_sarif.convert({}))["results"], [])


def fake(code, stdout="", stderr=""):
    calls = []

    def run(args, **_):
        calls.append(args)
        return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)

    return run, calls


LOCKFILES = Namespace(mode="lockfiles", registry=None, internal=[])


class Scan(unittest.TestCase):
    def test_the_lockfiles_mode_has_no_network_and_ignores_the_target_settings(self):
        args = osv_sarif.command("lockfiles")
        for flag in ("--offline", "--no-ignore", "--recursive"):
            self.assertIn(flag, args)
        self.assertEqual(args[args.index("--config") + 1], osv_sarif.CONFIG)
        self.assertEqual(args[args.index("--x-disable-plugins") + 1], "java/pomxml")

    def test_the_maven_mode_resolves_through_the_registry(self):
        args = osv_sarif.command("maven", "http://proxy:8080/maven2")
        self.assertEqual(args[args.index("--maven-registry") + 1], "http://proxy:8080/maven2")
        self.assertEqual(args[args.index("--data-source") + 1], "native")
        self.assertIn("--offline-vulnerabilities", args)
        self.assertNotIn("--offline", args)

    def test_flaws_found_is_a_success(self):
        run, _ = fake(1, json.dumps(report(LODASH)))
        code, sarif, _ = osv_sarif.scan(LOCKFILES, run)
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(sarif)["runs"][0]["results"]), 1)

    def test_no_lock_file_gives_an_empty_sarif(self):
        run, _ = fake(128, "", "No package sources found")
        code, sarif, _ = osv_sarif.scan(LOCKFILES, run)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(sarif)["runs"][0]["results"], [])

    def test_no_lock_file_and_no_database_gives_an_empty_sarif(self):
        stderr = "Error during extraction: could not create : mkdir /data\nNo package sources found"
        run, _ = fake(128, "", stderr)
        self.assertEqual(osv_sarif.scan(LOCKFILES, run)[0], 0)

    def test_an_error_fails(self):
        run, _ = fake(127, "", "could not load db for PyPI ecosystem")
        self.assertEqual(osv_sarif.scan(LOCKFILES, run)[:2], (2, None))

    def test_a_file_not_fully_read_fails_even_with_results(self):
        stderr = "Error during extraction: failed resolution for pom.xml"
        run, _ = fake(1, json.dumps(report(LODASH)), stderr)
        code, sarif, error = osv_sarif.scan(LOCKFILES, run)
        self.assertEqual((code, sarif), (2, None))
        self.assertIn("failed resolution", error)

    def test_an_output_that_is_not_json_fails(self):
        run, _ = fake(0, "not json")
        self.assertEqual(osv_sarif.scan(LOCKFILES, run)[0], 2)


POM = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <version>2.0</version>
  <properties><lib.version>3.0.19</lib.version></properties>
  <dependencies>
    <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId></dependency>
    <dependency><groupId>ch.vs.sci</groupId><artifactId>core</artifactId><version>${project.version}</version></dependency>
  </dependencies>
  <profiles><profile><id>sci</id><dependencies>
    <dependency><groupId>ch.vs.sci</groupId><artifactId>java-quarkus</artifactId><version>${lib.version}</version></dependency>
  </dependencies></profile></profiles>
</project>
"""


class InternalInPoms(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.dir, "api"))
        with open(os.path.join(self.dir, "api", "pom.xml"), "w") as file:
            file.write(POM)

    def test_the_internal_dependencies_are_found_also_in_a_profile(self):
        found = osv_sarif.internal_in_poms(self.dir, ["ch.vs."])
        pom = os.path.join(self.dir, "api", "pom.xml")
        self.assertEqual(found, [(pom, "ch.vs.sci:core", "2.0"), (pom, "ch.vs.sci:java-quarkus", "3.0.19")])

    def test_the_maven_mode_adds_them_once(self):
        listed = package("ch.vs.sci:core", "2.0")
        run, _ = fake(0, json.dumps(report(listed, path=os.path.join(self.dir, "api", "pom.xml"))))
        args = Namespace(mode="maven", registry="http://proxy:8080/maven2", internal=["ch.vs."])
        code, sarif, _ = osv_sarif.scan(args, run, self.dir)
        texts = [result["message"]["text"] for result in json.loads(sarif)["runs"][0]["results"]]
        self.assertEqual(code, 0)
        self.assertEqual(texts, [
            "Paquet interne, non vérifié ici : ch.vs.sci:core@2.0",
            "Paquet interne, non vérifié ici : ch.vs.sci:java-quarkus@3.0.19",
        ])

    def test_a_pom_that_is_not_xml_is_skipped(self):
        with open(os.path.join(self.dir, "api", "pom.xml"), "w") as file:
            file.write("not xml")
        self.assertEqual(osv_sarif.internal_in_poms(self.dir, ["ch.vs."]), [])


if __name__ == "__main__":
    unittest.main()
