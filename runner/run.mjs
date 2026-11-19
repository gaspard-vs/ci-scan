// Scans one repository: the detection, the stages, then the gate.
//
// The gate is closed. All that the runner cannot check blocks: a file with
// no owner, a technology that CI scan does not cover, a step that fails or
// gives a result that the runner cannot read.
import { copyFile, lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { prepareData } from './data.mjs'
import { assign, listFiles, parseDetection } from './detection.mjs'
import { launch as docker, imageKey } from './docker.mjs'
import { extrasOf, findingsOf, merge, notesOf, parseSarif } from './sarif.mjs'
import { nameMatches, readStages, readStep, readTechnologies } from './steps.mjs'

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

// Copies the chosen files of the repository into a new folder, at the same
// paths. A symbolic link is not copied.
async function copyFiles(repo, files) {
  const dir = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ci-scan-files-')))
  for (const file of files) {
    const source = path.join(repo, file)
    if (!(await lstat(source)).isFile()) continue
    await mkdir(path.dirname(path.join(dir, file)), { recursive: true })
    await copyFile(source, path.join(dir, file))
  }
  return dir
}

// What the proxy of a stage let out, for the report and the SARIF file.
function summary(requests) {
  return {
    total: requests.length,
    refused: requests.filter((request) => request.action === 'refused').length,
  }
}

// Prepares the data of a stage in the folder of the day, once: a mark next
// to the folder names the data and the image that prepared it. Gives the
// reason of a failure, or nothing.
async function prepareFolder(stage, data, { launch, timeout }) {
  const folder = path.join(data.dir, stage.prepare.folder)
  const mark = `${folder}.ready`
  const key = JSON.stringify({ image: await imageKey(stage), args: stage.prepare.args, data: data.checksums })
  if ((await readFile(mark, 'utf8').catch(() => null)) === key) return null
  await rm(mark, { force: true })
  await rm(folder, { recursive: true, force: true })
  await mkdir(folder)
  const result = await launch(stage, null, { timeout, dataDir: data.dir, prepareDir: folder })
  if (result.code !== 0) {
    await rm(folder, { recursive: true, force: true })
    return `préparation des données : ${result.stderr.trim().split('\n').pop() || `code ${result.code}`}`
  }
  await writeFile(mark, key)
  return null
}

// Writes the file that an earlier stage gave into a new folder, alone.
async function writeInput({ name, content }) {
  const dir = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ci-scan-input-')))
  await writeFile(path.join(dir, name), typeof content === 'string' ? content : JSON.stringify(content))
  return dir
}

// Runs one stage: its input, its files, its data, its container. Gives its
// result, or the reason why it could not run.
async function runStage(stage, repo, files, outputs, { launch, timeout, cacheDir, fetch }) {
  let input = null
  if (stage.input) {
    input = outputs.find((output) => output.name === stage.input)
    if (!input) return { reason: `entrée : aucune étape avant elle ne donne ${stage.input}` }
  }
  let data = null
  if (stage.data) {
    try {
      data = await prepareData(stage, files, { cacheDir, fetch })
    } catch (error) {
      return { reason: `données : ${error.message}` }
    }
  }
  if (data && stage.prepare) {
    const reason = await prepareFolder(stage, data, { launch, timeout })
    if (reason) return { reason, data }
  }
  const folders = []
  try {
    let copied = null
    if (stage.files) {
      copied = await copyFiles(repo, files.filter((file) => stage.files.some((p) => nameMatches(file, p))))
      folders.push(copied)
    }
    const inputDir = input ? await writeInput(input) : undefined
    if (inputDir) folders.push(inputDir)
    const result = await launch(stage, copied ?? repo, { timeout, dataDir: data?.dir, inputDir })
    return { result, data }
  } finally {
    for (const folder of folders) await rm(folder, { recursive: true, force: true })
  }
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
    cacheDir,
    fetch,
  } = options
  const repo = await realpath(target)
  const owners = JSON.parse(await readFile(path.join(policyDir, 'owners.json'), 'utf8'))
  const gate = JSON.parse(await readFile(path.join(policyDir, 'gate.json'), 'utf8'))
  const timeout = gate.stageTimeoutSeconds * 1000

  const detection = await readStep(detectionDir, 'detection.json', { stage: false })
  if (!detection) throw new Error(`${detectionDir}: the detection step is missing`)
  const technologies = await readTechnologies(techDir)

  const findings = []
  const notes = []
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
  const outputs = []
  for (const stage of stages) {
    const step = { id: stage.id, control: stage.control, count: null }
    steps.push(step)
    // A stage that reads only some files does not run without them.
    if (stage.files && !files.some((file) => stage.files.some((pattern) => nameMatches(file, pattern)))) {
      step.count = 0
      continue
    }
    const { result, data, reason } = await runStage(stage, repo, files, outputs, { launch, timeout, cacheDir, fetch })
    if (data) step.data = data.files
    if (result?.requests) step.requests = summary(result.requests)
    if (reason) {
      findings.push(failure(stage, null, reason))
    } else if (result.code !== 0) {
      findings.push(failure(stage, result))
    } else {
      try {
        const sarif = parseSarif(result.stdout)
        const extras = extrasOf(sarif)
        for (const output of extras.outputs) {
          if (outputs.some((known) => known.name === output.name)) throw new Error(`a stage already gives ${output.name}`)
        }
        const found = findingsOf(sarif, stage)
        for (const run of sarif.runs) {
          const extra = {}
          if (data) extra['ci-scan/data'] = data.files
          if (result.requests) extra['ci-scan/requests'] = result.requests
          if (Object.keys(extra).length) run.properties = { ...run.properties, ...extra }
        }
        runs.push(...sarif.runs)
        findings.push(...found)
        notes.push(...notesOf(sarif, stage))
        outputs.push(...extras.outputs)
        if (extras.summary) step.summary = extras.summary
        if (extras.outputs.length) step.outputs = extras.outputs.map((output) => output.name)
        step.count = found.length
      } catch (error) {
        findings.push(failure(stage, result, `résultat illisible (${error.message})`))
      }
    }
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
    notes,
    verdict: blocked ? 'bloqué' : 'conforme',
    outputs,
    sarif: merge(findings.filter((finding) => finding.source === 'ci-scan'), runs),
  }
}
