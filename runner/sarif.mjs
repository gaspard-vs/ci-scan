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

const WORDS = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'low' }

// The "security-severity" of a rule: a CVSS score, or a word. Undefined
// when it is absent or not known.
function gravityOf(severity) {
  if (typeof severity === 'string' && Object.hasOwn(WORDS, severity.trim().toLowerCase())) {
    return WORDS[severity.trim().toLowerCase()]
  }
  const score = Number.parseFloat(severity)
  if (Number.isNaN(score)) return undefined
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
      if (result.kind === 'informational') continue
      const set = stage.gravities && Object.hasOwn(stage.gravities, result.ruleId) ? stage.gravities[result.ruleId] : undefined
      const severity = gravityOf(rules.get(result.ruleId)?.properties?.['security-severity'])
      findings.push({
        source: stage.id,
        control: stage.control,
        title: result.ruleId ?? 'résultat',
        file: location?.artifactLocation?.uri,
        line: location?.region?.startLine,
        gravity: set ?? severity ?? stage.gravity,
      })
    }
  }
  return findings
}

// The results of a stage that are only for information. Call it after
// findingsOf, which makes the paths relative.
export function notesOf(sarif, stage) {
  const notes = []
  for (const run of sarif.runs) {
    for (const result of run.results) {
      if (result.kind !== 'informational') continue
      notes.push({
        source: stage.id,
        control: stage.control,
        title: result.message?.text ?? result.ruleId ?? 'information',
        file: result.locations?.[0]?.physicalLocation?.artifactLocation?.uri,
      })
    }
  }
  return notes
}

const OUTPUT_NAME = /^[a-z0-9][a-z0-9.-]*$/

// What a stage gives beside its results, in the properties of its runs:
//   - "ci-scan/output": a file, {"name", "content"}. The runner writes it
//     next to the report. It is removed from the SARIF: the SARIF of the scan
//     stays small. The name is short, with no folder;
//   - "ci-scan/summary": one line for the report.
export function extrasOf(sarif) {
  const outputs = []
  const summaries = []
  for (const run of sarif.runs) {
    const properties = run.properties ?? {}
    const summary = properties['ci-scan/summary']
    if (summary !== undefined) {
      if (typeof summary !== 'string' || /[\r\n]/.test(summary)) throw new Error('"ci-scan/summary" must be one line')
      summaries.push(summary)
    }
    const output = properties['ci-scan/output']
    if (output !== undefined) {
      if (typeof output?.name !== 'string' || !OUTPUT_NAME.test(output.name) || output.content === undefined) {
        throw new Error('"ci-scan/output" must give a short file "name" and a "content"')
      }
      if (outputs.some((known) => known.name === output.name)) throw new Error(`two files ${output.name}`)
      outputs.push({ name: output.name, content: output.content })
      delete properties['ci-scan/output']
    }
  }
  return { outputs, summary: summaries.join(', ') }
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
