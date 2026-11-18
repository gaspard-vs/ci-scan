// The data of a stage: download, cache and check. No network: the server is
// a fake.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readdir, readFile, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import { prepareData } from '../data.mjs'

const NOW = new Date('2026-11-18T10:00:00Z')
const md5 = (body) => createHash('md5').update(body).digest('base64')

const STEP = {
  id: 'osv',
  data: [
    { file: 'npm/all.zip', url: 'https://db.example/npm/all.zip', when: ['package-lock.json'] },
    { file: 'Maven/all.zip', url: 'https://db.example/Maven/all.zip', when: ['pom.xml'] },
  ],
}

// A server with one body for each address. `gets` counts the downloads.
function server(bodies, { hash = md5 } = {}) {
  const gets = []
  const fetch = async (url, init = {}) => {
    const body = bodies[url]
    if (body === undefined) return new Response(null, { status: 404 })
    const headers = { 'last-modified': 'Wed, 18 Nov 2026 09:33:00 GMT' }
    const value = hash(body)
    if (value) headers['x-goog-hash'] = `crc32c=AAAA==, md5=${value}`
    if (init.method === 'HEAD') return new Response(null, { headers })
    gets.push(url)
    return new Response(body, { headers })
  }
  return { fetch, gets }
}

const cache = () => mkdtemp(path.join(os.tmpdir(), 'ci-scan-cache-'))

test('only the files that the repository needs are downloaded', async () => {
  const cacheDir = await cache()
  const { fetch, gets } = server({ 'https://db.example/npm/all.zip': 'npm db', 'https://db.example/Maven/all.zip': 'maven db' })
  const data = await prepareData(STEP, ['ui/package-lock.json', 'README.md'], { cacheDir, fetch, now: NOW })
  assert.deepEqual(gets, ['https://db.example/npm/all.zip'])
  assert.equal(data.dir, path.join(cacheDir, 'data', '2026-11-18'))
  assert.deepEqual(data.files, [{ file: 'npm/all.zip', date: '2026-11-18T09:33:00.000Z' }])
  assert.equal(await readFile(path.join(data.dir, 'npm', 'all.zip'), 'utf8'), 'npm db')
})

test('no file needed: nothing is downloaded and nothing is mounted', async () => {
  const { fetch, gets } = server({})
  assert.equal(await prepareData(STEP, ['README.md'], { cacheDir: await cache(), fetch, now: NOW }), null)
  assert.deepEqual(gets, [])
})

test('a cached file with the MD5 of the server is used again', async () => {
  const cacheDir = await cache()
  const { fetch, gets } = server({ 'https://db.example/npm/all.zip': 'npm db' })
  await prepareData(STEP, ['package-lock.json'], { cacheDir, fetch, now: NOW })
  await prepareData(STEP, ['package-lock.json'], { cacheDir, fetch, now: NOW })
  assert.equal(gets.length, 1)
})

test('a cached file that the server does not give is downloaded again', async () => {
  const cacheDir = await cache()
  const target = path.join(cacheDir, 'data', '2026-11-18', 'npm', 'all.zip')
  await mkdir(path.dirname(target), { recursive: true })
  // A poisoned cache: an empty database under the right name.
  await writeFile(target, 'empty')
  const { fetch, gets } = server({ 'https://db.example/npm/all.zip': 'npm db' })
  await prepareData(STEP, ['package-lock.json'], { cacheDir, fetch, now: NOW })
  assert.equal(gets.length, 1)
  assert.equal(await readFile(target, 'utf8'), 'npm db')
})

test('a download that does not match its MD5 fails, and leaves no file', async () => {
  const cacheDir = await cache()
  const { fetch } = server({ 'https://db.example/npm/all.zip': 'npm db' }, { hash: () => md5('other') })
  await assert.rejects(prepareData(STEP, ['package-lock.json'], { cacheDir, fetch, now: NOW }), /MD5 .*, expected/)
  assert.deepEqual(await readdir(path.join(cacheDir, 'data', '2026-11-18', 'npm')), [])
})

test('a server that gives no MD5 fails: the file cannot be checked', async () => {
  const { fetch } = server({ 'https://db.example/npm/all.zip': 'npm db' }, { hash: () => undefined })
  await assert.rejects(
    prepareData(STEP, ['package-lock.json'], { cacheDir: await cache(), fetch, now: NOW }),
    /the server gives no MD5/,
  )
})

test('a server error fails', async () => {
  const { fetch } = server({})
  await assert.rejects(
    prepareData(STEP, ['package-lock.json'], { cacheDir: await cache(), fetch, now: NOW }),
    /HTTP 404/,
  )
})

test('the folders of the other days are deleted', async () => {
  const cacheDir = await cache()
  await mkdir(path.join(cacheDir, 'data', '2026-11-17', 'npm'), { recursive: true })
  const { fetch } = server({ 'https://db.example/npm/all.zip': 'npm db' })
  await prepareData(STEP, ['package-lock.json'], { cacheDir, fetch, now: NOW })
  assert.deepEqual(await readdir(path.join(cacheDir, 'data')), ['2026-11-18'])
})
