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

// The results of Opengrep: file, line, rule (without the folder) and gravity.
const opengrep = (found) =>
  found.findings
    .filter((finding) => finding.source === 'opengrep')
    .map((finding) => `${finding.file}:${finding.line} ${finding.title.split('.').pop()} ${finding.gravity}`)

const TLS_OFF = [
  'client.js:2 rules_lgpl_javascript_crypto_rule-node-tls-reject high',
  'src/main/java/ch/example/Insecure.java:12 java_endpoint_rule-X509TrustManager high',
  'src/main/java/ch/example/Insecure.java:14 java_endpoint_rule-X509TrustManager high',
  'src/main/java/ch/example/Insecure.java:16 java_endpoint_rule-X509TrustManager high',
  'src/main/java/ch/example/Insecure.java:22 java_endpoint_rule-HostnameVerifier high',
]

test('tls-off: bloqué, the certificate check is off', { skip }, async () => {
  const found = await run(fixture('tls-off'))
  assert.equal(found.verdict, 'bloqué')
  assert.deepEqual(opengrep(found), TLS_OFF)
})

test('opengrep-silenced: the comments and the ignore files have no effect', { skip }, async () => {
  const found = await run(fixture('opengrep-silenced'))
  assert.deepEqual(opengrep(found), TLS_OFF)
})

test('tests-off: bloqué, the tests do not run', { skip }, async () => {
  const found = await run(fixture('tests-off'))
  assert.equal(found.verdict, 'bloqué')
  assert.deepEqual(opengrep(found), [
    'pom.xml:8 tests-off-maven high',
    'src/app/app.spec.ts:2 tests-off-focus high',
    'src/app/app.spec.ts:3 tests-off-focus high',
  ])
})

test('open-access: bloqué, all paths are open to all', { skip }, async () => {
  const found = await run(fixture('open-access'))
  assert.deepEqual(blocking(found), ['src/main/resources/application.properties: stage.rules.open-access-quarkus'])
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
