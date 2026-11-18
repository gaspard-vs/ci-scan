// The public files that a stage reads at /data, for example a database of
// known flaws. The runner downloads them before the stage, only when the
// repository has a file that needs them.
//
// The files stay in a cache, one folder for each day (UTC). A cached file
// is used only if its MD5 is the MD5 that the server gives now. Anything
// can write the cache (on GitHub, a workflow of the target), so a file is
// never trusted for its name alone.
import { createHash } from 'node:crypto'
import { createReadStream, createWriteStream } from 'node:fs'
import { mkdir, readdir, rename, rm, stat } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { Readable, Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { nameMatches } from './steps.mjs'

export function defaultCacheDir() {
  return process.env.CI_SCAN_CACHE || path.join(os.homedir(), '.cache', 'ci-scan')
}

// The MD5 that the server gives, in base64: `x-goog-hash: md5=…` (Google
// Cloud Storage) or `Content-MD5`.
function md5Of(headers) {
  const goog = /(?:^|,)\s*md5=([A-Za-z0-9+/=]+)/.exec(headers.get('x-goog-hash') ?? '')
  return goog?.[1] ?? headers.get('content-md5') ?? undefined
}

async function md5OfFile(file) {
  const hash = createHash('md5')
  for await (const chunk of createReadStream(file)) hash.update(chunk)
  return hash.digest('base64')
}

async function exists(file) {
  try {
    return (await stat(file)).isFile()
  } catch {
    return false
  }
}

function dateOf(headers) {
  const value = headers.get('last-modified')
  const date = value ? new Date(value) : null
  return date && !Number.isNaN(date.getTime()) ? date.toISOString() : undefined
}

async function download(entry, target, fetch) {
  const response = await fetch(entry.url, { redirect: 'error' })
  if (!response.ok) throw new Error(`${entry.url}: HTTP ${response.status}`)
  const expected = md5Of(response.headers)
  if (!expected) throw new Error(`${entry.url}: the server gives no MD5`)
  await mkdir(path.dirname(target), { recursive: true })
  const part = `${target}.part`
  const hash = createHash('md5')
  const tee = new Transform({
    transform(chunk, _encoding, done) {
      hash.update(chunk)
      done(null, chunk)
    },
  })
  try {
    await pipeline(Readable.fromWeb(response.body), tee, createWriteStream(part))
    const actual = hash.digest('base64')
    if (actual !== expected) throw new Error(`${entry.url}: MD5 ${actual}, expected ${expected}`)
    await rename(part, target)
  } catch (error) {
    await rm(part, { force: true })
    throw error
  }
  return dateOf(response.headers)
}

// Gets the files that the repository needs. Gives the folder to mount at
// /data and the list of files with their date, or nothing when no file is
// needed. Throws when a file cannot be had or checked.
export async function prepareData(step, files, options = {}) {
  const { cacheDir = defaultCacheDir(), fetch = globalThis.fetch, now = new Date() } = options
  const needed = step.data.filter((entry) =>
    files.some((file) => entry.when.some((pattern) => nameMatches(file, pattern))),
  )
  if (!needed.length) return null

  const root = path.join(cacheDir, 'data')
  const day = now.toISOString().slice(0, 10)
  const dir = path.join(root, day)
  await mkdir(dir, { recursive: true })
  for (const name of await readdir(root)) {
    if (name !== day) await rm(path.join(root, name), { recursive: true, force: true })
  }

  const list = []
  for (const entry of needed) {
    const target = path.join(dir, entry.file)
    const head = await fetch(entry.url, { method: 'HEAD', redirect: 'error' })
    if (!head.ok) throw new Error(`${entry.url}: HTTP ${head.status}`)
    const expected = md5Of(head.headers)
    let date
    if (expected && (await exists(target)) && (await md5OfFile(target)) === expected) {
      date = dateOf(head.headers)
    } else {
      date = await download(entry, target, fetch)
    }
    list.push({ file: entry.file, date })
  }
  return { dir, files: list }
}
