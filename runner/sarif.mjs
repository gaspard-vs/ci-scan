// Reads the SARIF result of a stage.
import { REPO_MOUNT } from './docker.mjs'

export function parseSarif(stdout) {
  const sarif = JSON.parse(stdout)
  if (sarif?.version !== '2.1.0') throw new Error('not SARIF 2.1.0')
  if (!Array.isArray(sarif.runs)) throw new Error('SARIF has no runs')
  for (const run of sarif.runs) {
    if (!Array.isArray(run.results)) throw new Error('a SARIF run has no results')
  }
  return sarif
}

// The path of a file in the repository, from the path that the tool saw.
function relative(uri) {
  if (typeof uri !== 'string') return undefined
  let file = uri
  if (file.startsWith('file://')) file = decodeURIComponent(file.slice('file://'.length))
  if (file.startsWith(`${REPO_MOUNT}/`)) file = file.slice(REPO_MOUNT.length + 1)
  return file
}

// A CVSS score, as tools give it in "security-severity".
function gravityOf(score) {
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  return 'low'
}

// The results of a stage, in the form that the gate and the report use. The
// paths in the SARIF itself are also made relative to the repository.
export function findingsOf(sarif, stage) {
  const findings = []
  for (const run of sarif.runs) {
    const rules = new Map((run.tool?.driver?.rules ?? []).map((rule) => [rule.id, rule]))
    for (const result of run.results) {
      const location = result.locations?.[0]?.physicalLocation
      if (location?.artifactLocation) {
        location.artifactLocation.uri = relative(location.artifactLocation.uri)
      }
      const score = Number.parseFloat(rules.get(result.ruleId)?.properties?.['security-severity'])
      findings.push({
        source: stage.id,
        control: stage.control,
        title: result.ruleId ?? 'résultat',
        file: location?.artifactLocation?.uri,
        line: location?.region?.startLine,
        gravity: Number.isNaN(score) ? stage.gravity : gravityOf(score),
      })
    }
  }
  return findings
}

// One SARIF file for the whole scan: the results of the runner itself, then
// the run of each stage.
export function merge(own, runs) {
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'ci-scan' } },
        results: own.map((finding) => ({
          ruleId: finding.rule,
          level: 'error',
          message: { text: finding.title },
          locations: finding.file
            ? [{ physicalLocation: { artifactLocation: { uri: finding.file } } }]
            : [],
        })),
      },
      ...runs,
    ],
  }
}
