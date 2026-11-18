// Starts a step in its container. This is the only file that knows Docker.
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'

// Where a step finds the repository and its own folder, both read-only.
export const REPO_MOUNT = '/scan/repo'
export const STAGE_MOUNT = '/stage'

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

// The image of a step: fixed by digest, or built from the folder of the step.
async function imageOf(step) {
  if (step.image) return { image: step.image }
  if (built.has(step.dir)) return built.get(step.dir)
  const image = `ci-scan-${step.id}:${await folderHash(step.dir)}`
  let result = { image }
  const known = await exec('docker', ['image', 'inspect', image])
  if (known.code !== 0) {
    const build = await exec('docker', ['build', '--quiet', '--tag', image, step.dir])
    if (build.code !== 0) result = { error: `docker build: ${build.stderr.trim()}` }
  }
  built.set(step.dir, result)
  return result
}

// Runs one step on one repository. The container cannot write anywhere
// (except an empty /tmp in memory, if the step asks for it), has no
// privilege and, unless the step asks for it, has no network. The result
// leaves on the standard output.
export async function launch(step, repo, { timeout } = {}) {
  const { image, error } = await imageOf(step)
  if (error) return { code: null, stdout: '', stderr: error }
  const args = [
    'run', '--rm', '--read-only',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--user', `${process.getuid()}:${process.getgid()}`,
    '--volume', `${repo}:${REPO_MOUNT}:ro`,
    '--volume', `${step.dir}:${STAGE_MOUNT}:ro`,
  ]
  if (!step.network) args.push('--network', 'none')
  if (step.tmp) args.push('--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=1g')
  args.push(image, ...step.args)
  return exec('docker', args, { timeout })
}
