// Scans one repository: the detection, the stages, then the gate.
//
// The gate is closed. All that the runner cannot check blocks: a file with
// no owner, a technology that CI scan does not cover, a step that fails or
// gives a result that the runner cannot read.
import { readFile, realpath } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { assign, listFiles, parseDetection } from './detection.mjs'
import { launch as docker } from './docker.mjs'
import { findingsOf, merge, parseSarif } from './sarif.mjs'
import { readStages, readStep, readTechnologies } from './steps.mjs'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

const DETECTION = 'Détection'

function plural(count, word) {
  return `${count} ${word}${count > 1 ? 's' : ''}`
}

// A result of the runner itself. It always blocks.
function own(rule, control, title, file) {
  return { source: 'ci-scan', control, rule, title, file, gravity: 'critical' }
}

function failure(step, result, reason) {
  const detail = reason ?? (result.stderr.trim().split('\n').pop() || `code ${result.code}`)
  return own('step-failed', step.control, `L'étape « ${step.id} » n'a pas pu tourner : ${detail}`)
}

// Options, all with a default: the folders of CI scan, and `launch`, the
// function that starts a step (tests replace it).
export async function run(target, options = {}) {
  const {
    commonDir = path.join(ROOT, 'common'),
    techDir = path.join(ROOT, 'tech'),
    policyDir = path.join(ROOT, 'policy'),
    detectionDir = path.join(commonDir, 'detection'),
    launch = docker,
  } = options
  const repo = await realpath(target)
  const owners = JSON.parse(await readFile(path.join(policyDir, 'owners.json'), 'utf8'))
  const gate = JSON.parse(await readFile(path.join(policyDir, 'gate.json'), 'utf8'))
  const timeout = gate.stageTimeoutSeconds * 1000

  const detection = await readStep(detectionDir, 'detection.json', { stage: false })
  if (!detection) throw new Error(`${detectionDir}: the detection step is missing`)
  const technologies = await readTechnologies(techDir)

  const findings = []
  const steps = []

  // 1. The detection.
  const files = await listFiles(repo)
  let assigned = { technologies: [], uncovered: new Map(), unowned: [] }
  const counted = await launch(detection, repo, { timeout })
  if (counted.code !== 0) {
    findings.push(failure(detection, counted))
  } else {
    try {
      assigned = assign(files, parseDetection(counted.stdout), owners, technologies)
    } catch (error) {
      findings.push(failure(detection, counted, `résultat illisible (${error.message})`))
    }
  }
  for (const [language, list] of assigned.uncovered) {
    const title = `Technologie non couverte : ${language} (${plural(list.length, 'fichier')})`
    findings.push(own('uncovered-technology', DETECTION, title, list[0]))
  }
  for (const { file, reason } of assigned.unowned) {
    findings.push(own('unowned-file', DETECTION, `Fichier sans propriétaire : ${reason}`, file))
  }

  // 2. The common stages, then the stages of each technology found.
  const stages = await readStages(commonDir)
  for (const tech of technologies) {
    if (assigned.technologies.includes(tech.name)) stages.push(...(await readStages(tech.dir)))
  }
  const runs = []
  for (const stage of stages) {
    const result = await launch(stage, repo, { timeout })
    let found = null
    if (result.code !== 0) {
      findings.push(failure(stage, result))
    } else {
      try {
        const sarif = parseSarif(result.stdout)
        found = findingsOf(sarif, stage)
        runs.push(...sarif.runs)
        findings.push(...found)
      } catch (error) {
        findings.push(failure(stage, result, `résultat illisible (${error.message})`))
      }
    }
    steps.push({ id: stage.id, control: stage.control, count: found?.length ?? null })
  }

  // 3. The gate.
  for (const finding of findings) finding.blocks = gate.block.includes(finding.gravity)
  const blocked = findings.some((finding) => finding.blocks)

  return {
    repo,
    files: files.length,
    technologies: assigned.technologies,
    uncovered: [...assigned.uncovered.keys()].sort(),
    steps,
    findings,
    verdict: blocked ? 'bloqué' : 'conforme',
    sarif: merge(findings.filter((finding) => finding.source === 'ci-scan'), runs),
  }
}
