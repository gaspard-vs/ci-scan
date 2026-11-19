"""Runs Syft on /scan/repo and prints SARIF 2.1.0 that holds the SBOM.

The SBOM is in CycloneDX 1.6 JSON. It is not a result: the SARIF has no
result. The runner reads two properties of the run:

  ci-scan/output   {"name": "sbom.cdx.json", "content": <the SBOM>}. The
                   runner writes it next to the report, and removes it from
                   the SARIF of the scan.
  ci-scan/summary  One line for the report: the number of components.

The container can write nowhere: the SBOM leaves on the standard output,
like the results of the other stages.

Syft starts in /tmp with our settings (--config): it never reads the
settings of the target.

Exit code: 0 with a SARIF, or 2 when Syft fails or gives no valid SBOM. A
failure blocks the scan: the inventory is then missing.
"""

import json
import subprocess
import sys

REPO = "/scan/repo"
CONFIG = "/opt/ci-scan/syft.yaml"
OUTPUT = "sbom.cdx.json"
FORMAT = "cyclonedx-json@1.6"


def command(repo=REPO, config=CONFIG):
    return ["syft", "scan", f"dir:{repo}", "--config", config, "--output", FORMAT, "--quiet"]


def components(sbom):
    """The components of the SBOM, files excluded."""
    return [item for item in sbom.get("components") or [] if item.get("type") != "file"]


def summary(sbom):
    count = len(components(sbom))
    return f"{count} composant{'s' if count > 1 else ''}"


def version_of(sbom):
    for tool in (sbom.get("metadata", {}).get("tools") or {}).get("components") or []:
        if tool.get("name") == "syft":
            return tool.get("version")
    return None


def convert(sbom):
    driver = {"name": "syft", "informationUri": "https://github.com/anchore/syft"}
    version = version_of(sbom)
    if version:
        driver["version"] = version
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": driver},
            "results": [],
            "properties": {
                "ci-scan/summary": summary(sbom),
                "ci-scan/output": {"name": OUTPUT, "content": sbom},
            },
        }],
    }


def scan(run=subprocess.run):
    """Gives (exit code, SARIF, error)."""
    done = run(command(), cwd="/tmp", capture_output=True, text=True)
    if done.returncode != 0:
        return 2, "", f"syft: code {done.returncode}: {done.stderr.strip()}"
    try:
        sbom = json.loads(done.stdout)
    except json.JSONDecodeError as error:
        return 2, "", f"syft: the SBOM is not JSON ({error})"
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX":
        return 2, "", "syft: the SBOM is not CycloneDX"
    return 0, json.dumps(convert(sbom)), ""


def main():
    code, sarif, error = scan()
    if error:
        print(error, file=sys.stderr)
    if sarif:
        print(sarif)
    return code


if __name__ == "__main__":
    sys.exit(main())
