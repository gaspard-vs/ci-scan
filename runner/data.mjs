// The public files that a stage reads at /data, for example a database of
// known flaws. The runner downloads them before the stage, only when the
// repository has a file that needs them.
//
// An entry gives its address in one of two ways:
//   - "url": the file. The server gives its MD5 (OSV);
//   - "listing": a small JSON file that names the newest file, with its
//     sha256 and its date (Grype): {"path", "checksum": "sha256:…",
//     "built"}. "path" is read from the address of the listing, and must
//     stay on the same server.
//
// The files stay in a cache, one folder for each day (UTC). A cached file
// is used only if its checksum is the one that the server gives now.
// Anything can write the cache (on GitHub, a workflow of the target), so a
// file is never trusted for its name alone.
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

// A checksum: its algorithm, its encoding and its value.
const md5 = (value) => ({ algorithm: 'md5', encoding: 'base64', value, name: 'MD5' })
const sha256 = (value) => ({ algorithm: 'sha256', encoding: 'hex', value, name: 'sha256' })

async function checksumOfFile(file, { algorithm, encoding }) {
  const hash = createHash(algorithm)
  for await (const chunk of createReadStream(file)) hash.update(chunk)
  return hash.digest(encoding)
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

// Downloads a file and checks it. `expected` is the checksum, or nothing
// when the server gives it with the file (MD5). Gives the date of the file
// and its checksum.
async function download(url, target, fetch, expected) {
  const response = await fetch(url, { redirect: 'error' })
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`)
  const given = md5Of(response.headers)
  const checksum = expected ?? (given && md5(given))
  if (!checksum) throw new Error(`${url}: the server gives no MD5`)
  await mkdir(path.dirname(target), { recursive: true })
  const part = `${target}.part`
  const hash = createHash(checksum.algorithm)
  const tee = new Transform({
    transform(chunk, _encoding, done) {
      hash.update(chunk)
      done(null, chunk)
    },
  })
  try {
    await pipeline(Readable.fromWeb(response.body), tee, createWriteStream(part))
    const actual = hash.digest(checksum.encoding)
    if (actual !== checksum.value) throw new Error(`${url}: ${checksum.name} ${actual}, expected ${checksum.value}`)
    await rename(part, target)
  } catch (error) {
    await rm(part, { force: true })
    throw error
  }
  return { date: dateOf(response.headers), checksum: `${checksum.algorithm}:${checksum.value}` }
}

// The newest file that a listing names: its address, its sha256 and its
// date.
async function readListing(entry, fetch) {
  const response = await fetch(entry.listing, { redirect: 'error' })
  if (!response.ok) throw new Error(`${entry.listing}: HTTP ${response.status}`)
  let listing
  try {
    listing = await response.json()
  } catch {
    throw new Error(`${entry.listing}: not JSON`)
  }
  const fail = (message) => {
    throw new Error(`${entry.listing}: ${message}`)
  }
  if (typeof listing?.path !== 'string' || !listing.path) fail('no "path"')
  const url = new URL(listing.path, entry.listing)
  if (url.origin !== new URL(entry.listing).origin) fail(`"path" leaves the server: ${url}`)
  const checksum = /^sha256:([0-9a-f]{64})$/.exec(listing.checksum ?? '')
  if (!checksum) fail('no "checksum" sha256')
  const built = new Date(listing.built)
  return {
    url: url.href,
    checksum: sha256(checksum[1]),
    date: Number.isNaN(built.getTime()) ? undefined : built.toISOString(),
  }
}

// Gets one file in the cache. Gives its date and its checksum.
async function getFile(entry, target, fetch) {
  if (entry.listing) {
    const { url, checksum, date } = await readListing(entry, fetch)
    if (!(await exists(target)) || (await checksumOfFile(target, checksum)) !== checksum.value) {
      await download(url, target, fetch, checksum)
    }
    return { date, checksum: `sha256:${checksum.value}` }
  }
  const head = await fetch(entry.url, { method: 'HEAD', redirect: 'error' })
  if (!head.ok) throw new Error(`${entry.url}: HTTP ${head.status}`)
  const value = md5Of(head.headers)
  if (value && (await exists(target)) && (await checksumOfFile(target, md5(value))) === value) {
    return { date: dateOf(head.headers), checksum: `md5:${value}` }
  }
  return download(entry.url, target, fetch)
}

// Gets the files that the repository needs. Gives the folder to mount at
// /data, the list of files with their date, and their checksums; or
// nothing when no file is needed. Throws when a file cannot be had or
// checked.
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
  const checksums = []
  for (const entry of needed) {
    const { date, checksum } = await getFile(entry, path.join(dir, entry.file), fetch)
    list.push({ file: entry.file, date })
    checksums.push(`${entry.file} ${checksum}`)
  }
  return { dir, files: list, checksums }
}
