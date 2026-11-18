// Reads the steps of CI scan from its folders. A step is a folder with one
// JSON file. The runner knows no tool: it knows only this contract.
//
// The contract of a step:
//   - the container gets the repository at /scan/repo and the folder of the
//     step at /stage, both read-only;
//   - it prints its result on the standard output and ends with code 0;
//   - a stage prints SARIF 2.1.0; the detection prints one JSON line per file.
import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'

export const GRAVITIES = ['critical', 'high', 'medium', 'low']

const DIGEST = /@sha256:[0-9a-f]{64}$/

async function readJson(file) {
  try {
    return JSON.parse(await readFile(file, 'utf8'))
  } catch (error) {
    if (error.code === 'ENOENT') return null
    throw new Error(`${file}: ${error.message}`)
  }
}

function check(step, file, { stage }) {
  const fail = (message) => {
    throw new Error(`${file}: ${message}`)
  }
  if (typeof step.id !== 'string' || !/^[a-z0-9-]+$/.test(step.id)) fail('"id" must be a short name')
  if (typeof step.control !== 'string' || !step.control) fail('"control" is missing')
  if (step.build === true ? step.image !== undefined : typeof step.image !== 'string') {
    fail('give "image" or "build": true, and only one')
  }
  if (step.image && !DIGEST.test(step.image)) fail('"image" must end with its sha256 digest')
  if (!Array.isArray(step.args) || step.args.some((arg) => typeof arg !== 'string')) {
    fail('"args" must be a list of strings')
  }
  if (step.network !== undefined && typeof step.network !== 'boolean') fail('"network" must be true or false')
  if (stage && !GRAVITIES.includes(step.gravity)) fail(`"gravity" must be one of ${GRAVITIES.join(', ')}`)
}

export async function readStep(dir, name, { stage }) {
  const file = path.join(dir, name)
  const step = await readJson(file)
  if (!step) return null
  check(step, file, { stage })
  return { ...step, dir }
}

async function folders(dir) {
  try {
    const entries = await readdir(dir, { withFileTypes: true })
    return entries.filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort()
  } catch (error) {
    if (error.code === 'ENOENT') return []
    throw error
  }
}

// The stages of one folder, in the order of the folder names.
export async function readStages(dir) {
  const stages = []
  for (const name of await folders(dir)) {
    const stage = await readStep(path.join(dir, name), 'stage.json', { stage: true })
    if (stage) stages.push(stage)
  }
  return stages
}

// The technologies that CI scan covers: one folder each, with the languages
// that it owns.
export async function readTechnologies(dir) {
  const technologies = []
  for (const name of await folders(dir)) {
    const file = path.join(dir, name, 'tech.json')
    const tech = await readJson(file)
    if (!tech) throw new Error(`${file}: missing`)
    if (!Array.isArray(tech.languages) || !tech.languages.length) {
      throw new Error(`${file}: "languages" must be a list`)
    }
    technologies.push({ name, languages: tech.languages, dir: path.join(dir, name) })
  }
  return technologies
}
