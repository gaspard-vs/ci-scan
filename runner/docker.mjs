// Starts a step in its container. This is the only file that knows Docker.
import { spawn } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'

// Where a step finds the repository, its own folder, its data and the file
// of an earlier stage, all read-only.
export const REPO_MOUNT = '/scan/repo'
export const STAGE_MOUNT = '/stage'
export const DATA_MOUNT = '/data'
export const INPUT_MOUNT = '/input'
// The only folder where the preparation of the data can write.
export const PREPARE_MOUNT = '/prepare'

function exec(command, args, { timeout } = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] })
    const out = []
    const err = []
    let timedOut = false
    const timer = timeout
      ? setTimeout(() => {
          timedOut = true
          child.kill('SIGKILL')
        }, timeout)
      : null
    child.stdout.on('data', (chunk) => out.push(chunk))
    child.stderr.on('data', (chunk) => err.push(chunk))
    const done = (code, extra = '') => {
      clearTimeout(timer)
      resolve({
        code: timedOut ? null : code,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8') + extra + (timedOut ? '\ntimeout' : ''),
      })
    }
    child.on('error', (error) => done(null, String(error)))
    child.on('close', (code) => done(code))
  })
}

// A hash of all the files of a folder: the name of a built image changes
// when one of its inputs changes.
async function folderHash(dir) {
  const hash = createHash('sha256')
  const entries = await readdir(dir, { recursive: true, withFileTypes: true })
  const files = entries
    .filter((entry) => entry.isFile())
    .map((entry) => path.join(entry.parentPath, entry.name))
    .sort()
  for (const file of files) {
    hash.update(path.relative(dir, file))
    hash.update('\0')
    hash.update(await readFile(file))
    hash.update('\0')
  }
  return hash.digest('hex').slice(0, 16)
}

const built = new Map()

// The image built from a folder with a Dockerfile. Its name changes when a
// file of the folder changes.
export async function buildImage(dir, name) {
  if (built.has(dir)) return built.get(dir)
  const image = `ci-scan-${name}:${await folderHash(dir)}`
  let result = { image }
  const known = await exec('docker', ['image', 'inspect', image])
  if (known.code !== 0) {
    const build = await exec('docker', ['build', '--quiet', '--tag', image, dir])
    if (build.code !== 0) result = { error: `docker build: ${build.stderr.trim()}` }
  }
  built.set(dir, result)
  return result
}

// The image of a step: fixed by digest, or built from the folder of the
// step, or from the folder that "build" names.
function imageOf(step) {
  if (step.image) return { image: step.image }
  if (step.build === true) return buildImage(step.dir, step.id)
  const dir = path.resolve(step.dir, step.build)
  return buildImage(dir, path.basename(dir))
}

const PROXY_ALIAS = 'proxy'
const PROXY_READY_MS = 15_000

// The options that close a container: no write (except an empty /tmp in
// memory, if asked), no privilege, the user of the runner.
function closed(step) {
  const args = [
    '--read-only',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--user', `${process.getuid()}:${process.getgid()}`,
  ]
  if (step.tmp) args.push('--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=1g')
  return args
}

// Starts the proxy of a step on a new network with no route out. The proxy
// itself has the network. Gives the network, the container and a function
// that stops both and gives the lines of the proxy.
async function startProxy(step) {
  const { image, error } = await buildImage(path.resolve(step.dir, step.proxy.build), `${step.id}-proxy`)
  if (error) return { error }
  const name = `ci-scan-${step.id}-${randomBytes(4).toString('hex')}`
  const stop = async () => {
    const logs = await exec('docker', ['logs', name])
    await exec('docker', ['rm', '--force', name])
    await exec('docker', ['network', 'rm', name])
    return logs.stdout
  }
  const network = await exec('docker', ['network', 'create', '--internal', name])
  if (network.code !== 0) return { error: `docker network: ${network.stderr.trim()}` }
  let failed = await exec('docker', ['run', '--detach', '--name', name, ...closed({}), image, ...step.proxy.args])
  if (failed.code === 0) failed = await exec('docker', ['network', 'connect', '--alias', PROXY_ALIAS, name, name])
  if (failed.code !== 0) {
    await stop()
    return { error: `proxy: ${failed.stderr.trim()}` }
  }
  // The proxy prints {"ready": …} when it listens.
  const until = Date.now() + PROXY_READY_MS
  for (;;) {
    const logs = await exec('docker', ['logs', name])
    if (logs.stdout.includes('"ready"')) break
    if (Date.now() > until) {
      await stop()
      return { error: `proxy: not ready after ${PROXY_READY_MS / 1000} s ${logs.stderr.trim()}` }
    }
    await new Promise((resolve) => setTimeout(resolve, 200))
  }
  return { network: name, stop }
}

// The requests that the proxy saw: one JSON line each.
function requestsOf(stdout) {
  const requests = []
  for (const line of stdout.split('\n')) {
    if (!line.trim()) continue
    try {
      const entry = JSON.parse(line)
      if (entry && typeof entry.path === 'string') requests.push(entry)
    } catch {
      requests.push({ path: line, action: 'unreadable' })
    }
  }
  return requests
}

// What the image of a step comes from: its digest, or the hash of the
// folder that builds it. A prepared folder is reused only with the same
// image.
export async function imageKey(step) {
  if (step.image) return step.image
  const dir = step.build === true ? step.dir : path.resolve(step.dir, step.build)
  return `build:${await folderHash(dir)}`
}

// Prepares the data of a stage, once a day: the image of the stage, with
// "prepare.args", reads the data at /data and writes in prepareDir only,
// at /prepare. No repository, no input, no network.
async function prepare(step, image, { timeout, dataDir, prepareDir }) {
  const args = [
    'run', '--rm', ...closed(step),
    '--volume', `${step.dir}:${STAGE_MOUNT}:ro`,
    '--volume', `${dataDir}:${DATA_MOUNT}:ro`,
    '--volume', `${prepareDir}:${PREPARE_MOUNT}`,
    '--network', 'none',
    image, ...step.prepare.args,
  ]
  return exec('docker', args, { timeout })
}

// Runs one step on one repository. The container cannot write anywhere
// (except an empty /tmp in memory, if the step asks for it), has no
// privilege and has no network: unless the step asks for the network, or
// for a proxy, its only way out. The result leaves on the standard output.
// With prepareDir, it prepares the data of the stage instead.
export async function launch(step, repo, { timeout, dataDir, inputDir, prepareDir } = {}) {
  const { image, error } = await imageOf(step)
  if (error) return { code: null, stdout: '', stderr: error }
  if (prepareDir) return prepare(step, image, { timeout, dataDir, prepareDir })
  const args = [
    'run', '--rm', ...closed(step),
    '--volume', `${repo}:${REPO_MOUNT}:ro`,
    '--volume', `${step.dir}:${STAGE_MOUNT}:ro`,
  ]
  if (dataDir) args.push('--volume', `${dataDir}:${DATA_MOUNT}:ro`)
  if (inputDir) args.push('--volume', `${inputDir}:${INPUT_MOUNT}:ro`)
  for (const [name, value] of Object.entries(step.env ?? {})) args.push('--env', `${name}=${value}`)
  if (!step.proxy) {
    if (!step.network) args.push('--network', 'none')
    args.push(image, ...step.args)
    return exec('docker', args, { timeout })
  }
  const proxy = await startProxy(step)
  if (proxy.error) return { code: null, stdout: '', stderr: proxy.error }
  let result
  try {
    args.push('--network', proxy.network, image, ...step.args)
    result = await exec('docker', args, { timeout })
  } finally {
    const lines = await proxy.stop()
    if (result) result.requests = requestsOf(lines)
  }
  return result
}
