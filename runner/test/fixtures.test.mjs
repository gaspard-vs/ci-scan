// The whole scan on the fixtures, with the real containers.
//
// On a workstation where Docker does not run, these tests are skipped. In CI
// they always run.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import path from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { run } from '../run.mjs'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const fixture = (name) => path.join(ROOT, 'fixtures', name)

const docker = spawnSync('docker', ['info'], { stdio: 'ignore' }).status === 0
const skip = !docker && !process.env.CI ? 'Docker does not run' : false

const blocking = (found) =>
  found.findings.filter((finding) => finding.blocks).map((finding) => `${finding.file}: ${finding.rule ?? finding.title}`)

const SECRET = 'config.properties: generic-api-key'

test('clean: conforme', { skip }, async () => {
  const found = await run(fixture('clean'))
  assert.deepEqual(found.findings, [])
  assert.equal(found.verdict, 'conforme')
  assert.equal(found.files, 4)
})

test('secret: bloqué by the false key', { skip }, async () => {
  const found = await run(fixture('secret'))
  assert.equal(found.verdict, 'bloqué')
  assert.deepEqual(blocking(found), [SECRET])
  assert.equal(found.findings[0].line, 3)
})

test('silenced: a gitleaks:allow comment has no effect', { skip }, async () => {
  const found = await run(fixture('silenced'))
  assert.deepEqual(blocking(found), [SECRET])
})

test('own-config: the settings of the target have no effect', { skip }, async () => {
  const found = await run(fixture('own-config'))
  assert.equal(found.verdict, 'bloqué')
  assert.ok(blocking(found).includes(SECRET))
})

test('unknown-tech: bloqué, technologie non couverte', { skip }, async () => {
  const found = await run(fixture('unknown-tech'))
  assert.deepEqual(blocking(found), ['tool.py: uncovered-technology'])
  assert.deepEqual(found.uncovered, ['Python'])
})

test('unowned-file: bloqué, fichier sans propriétaire', { skip }, async () => {
  const found = await run(fixture('unowned-file'))
  assert.deepEqual(blocking(found), ['blob.bin: unowned-file'])
})

test('broken-stage: a stage that gives no result blocks', { skip }, async () => {
  const found = await run(fixture('clean'), {
    commonDir: fixture('stages/broken'),
    detectionDir: path.join(ROOT, 'common', 'detection'),
  })
  assert.equal(found.verdict, 'bloqué')
  assert.deepEqual(blocking(found), ['undefined: step-failed'])
  assert.deepEqual(found.steps, [{ id: 'broken', control: 'Essai', count: null }])
})
