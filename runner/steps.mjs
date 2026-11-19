// Reads the steps of CI scan from its folders. A step is a folder with one
// JSON file. The runner knows no tool: it knows only this contract.
//
// The contract of a step:
//   - the container gets the repository at /scan/repo and the folder of the
//     step at /stage, both read-only;
//   - with "tmp": true, it also gets an empty /tmp in memory, deleted at
//     the end, for a tool that cannot work without it;
//   - it prints its result on the standard output and ends with code 0;
//   - a stage prints SARIF 2.1.0; the detection prints one JSON line per file.
//
// A stage can also ask for:
//   - "env": environment variables;
//   - "files": name patterns. The stage sees only copies of these files,
//     and it does not run when the repository has none;
//   - "data": public files that the runner downloads before the stage, when
//     the repository has a file that needs them. The stage reads them at
//     /data, read-only. Each file comes from a "url" (the server gives its
//     MD5) or from a "listing" (a JSON file that names the newest file and
//     its sha256);
//   - "prepare": {"folder", "args"}, with "data". Once a day, after the
//     download, the image of the stage runs with these args: it reads the
//     data at /data and writes only in an empty folder, at /prepare. No
//     repository, no network. The stage then reads this folder at
//     /data/<folder>. The runner reuses it the same day only when the data
//     and the image are the same. A failure blocks the stage;
//   - "input": the name of a file that an earlier stage gives, such as
//     "sbom.cdx.json". The stage reads it at /input, read-only. Without
//     this file, the stage does not run, and the scan blocks;
//   - "proxy": its only way out. The stage is on a network with no route
//     out, where it reaches only this proxy, at http://proxy:8080. The proxy
//     prints one JSON line for each request. "build" is the folder of the
//     proxy, from the step folder: two stages can share one proxy.
//
// A stage can also give, in the properties of a SARIF run:
//   - "ci-scan/output": one file, {"name", "content"}, such as the SBOM. The
//     runner writes it next to the report (--out). The container itself
//     still writes nowhere;
//   - "ci-scan/summary": one line for the report.
//
// "build" is true (the Dockerfile of the step folder) or the path of another
// step folder, to share its image.
//
// The gravity of a result: "gravities" of the stage for its rule, else the
// "security-severity" of the rule (a CVSS score or a word), else "gravity".
// A result with "kind": "informational" is listed for information: it is not
// a result, and it never blocks.
import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'

export const GRAVITIES = ['critical', 'high', 'medium', 'low']

const DIGEST = /@sha256:[0-9a-f]{64}$/
const ENV_NAME = /^[A-Z_][A-Z0-9_]*$/
const PATTERN = /^[A-Za-z0-9._*-]+$/
// The name of a file that a stage gives: short, with no folder.
export const OUTPUT_NAME = /^[a-z0-9][a-z0-9.-]*$/

const isStrings = (value) => Array.isArray(value) && value.every((item) => typeof item === 'string')
const isPatterns = (value) => isStrings(value) && value.length > 0 && value.every((item) => PATTERN.test(item))
const isInside = (value) =>
  typeof value === 'string' && value !== '' && !path.isAbsolute(value) && !value.split('/').includes('..')

// A name pattern: the name of a file, with "*" for any text. It applies to
// the last part of the path.
export function nameMatches(file, pattern) {
  const name = file.split('/').pop()
  const source = pattern.split('*').map((part) => part.replace(/[.+?^${}()|[\]\\-]/g, '\\$&')).join('.*')
  return new RegExp(`^${source}$`).test(name)
}

function isBuild(build) {
  return build === true || (typeof build === 'string' && build !== '' && !path.isAbsolute(build))
}

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
  if (step.build !== undefined ? !isBuild(step.build) || step.image !== undefined : typeof step.image !== 'string') {
    fail('give "image" or "build" (true, or the path of a step folder), and only one')
  }
  if (step.image && !DIGEST.test(step.image)) fail('"image" must end with its sha256 digest')
  if (!isStrings(step.args)) fail('"args" must be a list of strings')
  if (step.network !== undefined && typeof step.network !== 'boolean') fail('"network" must be true or false')
  if (step.tmp !== undefined && typeof step.tmp !== 'boolean') fail('"tmp" must be true or false')
  if (step.env !== undefined) {
    const valid =
      typeof step.env === 'object' &&
      !Array.isArray(step.env) &&
      Object.entries(step.env).every(([name, value]) => ENV_NAME.test(name) && typeof value === 'string')
    if (!valid) fail('"env" must give a text for each NAME')
  }
  if (step.files !== undefined && !isPatterns(step.files)) fail('"files" must be a list of file name patterns')
  if (step.data !== undefined) {
    const isHttps = (value) => typeof value === 'string' && value.startsWith('https://')
    const valid =
      Array.isArray(step.data) &&
      step.data.every(
        (entry) =>
          isInside(entry?.file) &&
          (entry.url === undefined) !== (entry.listing === undefined) &&
          isHttps(entry.url ?? entry.listing) &&
          isPatterns(entry.when),
      )
    if (!valid) fail('"data" must give "file", an https "url" or "listing" (one only) and "when" for each entry')
  }
  if (step.prepare !== undefined) {
    const valid =
      typeof step.prepare?.folder === 'string' &&
      OUTPUT_NAME.test(step.prepare.folder) &&
      isStrings(step.prepare.args) &&
      Array.isArray(step.data)
    if (!valid) fail('"prepare" must give "folder" (a short name) and "args", with "data"')
  }
  if (step.input !== undefined &&!(typeof step.input === 'string' && OUTPUT_NAME.test(step.input))) {
    fail('"input" must be the short name of a file that an earlier stage gives')
  }
  if (step.proxy !== undefined) {
    const build = step.proxy?.build
    const valid = typeof build === 'string' && build !== '' && !path.isAbsolute(build) && isStrings(step.proxy.args)
    if (!valid) fail('"proxy" must give "build" (a folder, from the step folder) and "args"')
    if (step.network === true) fail('give "network" or "proxy", not both')
  }
  if (stage && !GRAVITIES.includes(step.gravity)) fail(`"gravity" must be one of ${GRAVITIES.join(', ')}`)
  if (step.gravities !== undefined) {
    const valid =
      stage &&
      typeof step.gravities === 'object' &&
      !Array.isArray(step.gravities) &&
      Object.values(step.gravities).every((gravity) => GRAVITIES.includes(gravity))
    if (!valid) fail(`"gravities" must give one of ${GRAVITIES.join(', ')} for each rule`)
  }
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
