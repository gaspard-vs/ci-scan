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

// The results of the OSV stages: file, rule (package and flaw) and gravity.
// The database changes each hour: a test asks for one known flaw, not for
// the whole list.
const osv = (found) =>
  found.findings
    .filter((finding) => finding.source.startsWith('osv'))
    .map((finding) => `${finding.file} ${finding.title} ${finding.gravity}`)

const LODASH = 'package-lock.json lodash@4.17.15 CVE-2020-8203 high'

test('vulnerable-npm: bloqué by a known flaw', { skip }, async () => {
  const found = await run(fixture('vulnerable-npm'))
  assert.equal(found.verdict, 'bloqué')
  assert.ok(osv(found).includes(LODASH), osv(found).join('\n'))
  assert.deepEqual(found.steps.find((step) => step.id === 'osv').data.map((data) => data.file), [
    'osv-scalibr/npm/all.zip',
  ])
})

test('malicious-npm: bloqué by a malicious package, critical', { skip }, async () => {
  const found = await run(fixture('malicious-npm'))
  assert.ok(osv(found).includes('package-lock.json flatmap-stream@0.1.1 MAL-2025-20690 critical'), osv(found).join('\n'))
})

test('osv-silenced: the settings and the ignore file of the target have no effect', { skip }, async () => {
  const found = await run(fixture('osv-silenced'))
  assert.ok(osv(found).includes(LODASH), osv(found).join('\n'))
})

// The requests that the helper of the Maven stage saw.
const requests = (found) => found.sarif.runs.flatMap((run) => run.properties?.['ci-scan/requests'] ?? [])

test('vulnerable-maven: bloqué by Log4Shell, through the helper only', { skip }, async () => {
  const found = await run(fixture('vulnerable-maven'))
  assert.ok(
    osv(found).includes('pom.xml org.apache.logging.log4j:log4j-core@2.14.1 CVE-2021-44228 critical'),
    osv(found).join('\n'),
  )
  const step = found.steps.find((entry) => entry.id === 'osv-maven')
  assert.ok(step.requests.total > 0)
  assert.equal(step.requests.refused, 0)
})

test('maven-snapshot: an internal SNAPSHOT does not stop the stage, and keeps its version', { skip }, async () => {
  const found = await run(fixture('maven-snapshot'))
  assert.ok(
    osv(found).includes('pom.xml org.apache.logging.log4j:log4j-core@2.14.1 CVE-2021-44228 critical'),
    osv(found).join('\n'),
  )
  assert.deepEqual(
    found.notes.map((note) => `${note.file}: ${note.title}`),
    ['pom.xml: Paquet interne, non vérifié ici : ch.vs.example:internal-lib@3.2.0-SNAPSHOT'],
  )
  const seen = requests(found)
  assert.ok(seen.some((request) => request.action === 'internal' && request.path.includes('/internal-lib/3.2.0/')))
  assert.deepEqual(seen.filter((request) => request.action !== 'internal' && request.path.includes('/ch/vs/')), [])
})

test('maven-resolved: the parent gives the version, and the internal package never leaves', { skip }, async () => {
  const found = await run(fixture('maven-resolved'))
  // snakeyaml has no version in pom.xml: only the parent gives it.
  assert.ok(osv(found).some((line) => line.startsWith('pom.xml org.yaml:snakeyaml@1.28 ')), osv(found).join('\n'))
  assert.deepEqual(
    found.notes.map((note) => `${note.file}: ${note.title}`),
    ['pom.xml: Paquet interne, non vérifié ici : ch.vs.example:internal-lib@1.0'],
  )
  const seen = requests(found)
  assert.ok(seen.some((request) => request.action === 'internal' && request.path.includes('/ch/vs/')))
  assert.deepEqual(seen.filter((request) => request.action !== 'internal' && request.path.includes('/ch/vs/')), [])
  assert.deepEqual(seen.filter((request) => request.action === 'refused'), [])
})

// The components of the SBOM that the Syft stage gives: their purl.
function sbom(found) {
  const [output] = found.outputs.filter((entry) => entry.name === 'sbom.cdx.json')
  assert.ok(output, 'no SBOM')
  assert.equal(output.content.bomFormat, 'CycloneDX')
  assert.equal(output.content.specVersion, '1.6')
  return (output.content.components ?? []).map((component) => component.purl).sort()
}

const MIXED = ['pkg:maven/org.apache.commons/commons-text@1.10.0', 'pkg:npm/lodash@4.17.21']

test('sbom-mixed: the SBOM lists the npm and the Maven components', { skip }, async () => {
  const found = await run(fixture('sbom-mixed'))
  const purls = sbom(found)
  for (const purl of MIXED) assert.ok(purls.includes(purl), purls.join('\n'))
  const step = found.steps.find((entry) => entry.id === 'syft')
  const { requests, ...rest } = step
  assert.deepEqual(rest, { id: 'syft', control: 'Inventaire des composants', count: 0, summary: '4 composants', outputs: ['sbom.cdx.json'] })
  assert.equal(requests.refused, 0)
  // The SBOM is not in the SARIF of the scan.
  assert.ok(!JSON.stringify(found.sarif).includes('CycloneDX'))
})

test('sbom-jar: a library delivered as a .jar file is in the SBOM', { skip }, async () => {
  const found = await run(fixture('sbom-jar'))
  assert.deepEqual(sbom(found), ['pkg:maven/org.apache.commons/commons-text@1.9'])
})

test('sbom-silenced: the settings of the target have no effect on the SBOM', { skip }, async () => {
  const found = await run(fixture('sbom-silenced'))
  const purls = sbom(found)
  for (const purl of MIXED) assert.ok(purls.includes(purl), purls.join('\n'))
})

test('maven-resolved: the SBOM has the version that the parent gives, and the internal package never leaves', { skip }, async () => {
  const found = await run(fixture('maven-resolved'))
  const purls = sbom(found)
  assert.ok(purls.includes('pkg:maven/org.yaml/snakeyaml@1.28'), purls.join('\n'))
  assert.ok(purls.includes('pkg:maven/ch.vs.example/internal-lib@1.0'), purls.join('\n'))
  const step = found.steps.find((entry) => entry.id === 'syft')
  assert.ok(step.requests.total > 0)
  assert.equal(step.requests.refused, 0)
  const seen = found.sarif.runs.find((entry) => entry.tool.driver.name === 'syft').properties['ci-scan/requests']
  assert.deepEqual(seen.filter((request) => request.action !== 'internal' && request.path.includes('/ch/vs/')), [])
})

test('clean: the SBOM has no component', { skip }, async () => {
  const found = await run(fixture('clean'))
  assert.deepEqual(sbom(found), [])
  assert.equal(found.steps.find((entry) => entry.id === 'syft').summary, '0 composant')
})

// The results of the Grype stage: file, rule (package and flaw) and gravity.
// The database changes each day: a test asks for one known flaw.
const grype = (found) =>
  found.findings
    .filter((finding) => finding.source === 'grype')
    .map((finding) => `${finding.file} ${finding.title} ${finding.gravity}`)

test('sbom-jar: Grype finds the flaw of a library delivered as a .jar file, and OSV does not', { skip }, async () => {
  const found = await run(fixture('sbom-jar'))
  assert.ok(
    grype(found).includes('lib/commons-text-1.9.jar org.apache.commons:commons-text@1.9 CVE-2022-42889 critical'),
    grype(found).join('\n'),
  )
  assert.deepEqual(osv(found), [])
  const step = found.steps.find((entry) => entry.id === 'grype')
  assert.deepEqual(step.data.map((data) => data.file), ['grype/vulnerability-db.tar.zst'])
})

test('vulnerable-maven: Grype also finds Log4Shell, from the SBOM', { skip }, async () => {
  const found = await run(fixture('vulnerable-maven'))
  assert.ok(
    grype(found).includes('pom.xml org.apache.logging.log4j:log4j-core@2.14.1 CVE-2021-44228 critical'),
    grype(found).join('\n'),
  )
})

const LODASH_GRYPE = 'package-lock.json lodash@4.17.15 CVE-2020-8203 high'

test('vulnerable-npm: Grype gives the same name as OSV', { skip }, async () => {
  const found = await run(fixture('vulnerable-npm'))
  assert.ok(grype(found).includes(LODASH_GRYPE), grype(found).join('\n'))
  assert.ok(osv(found).includes(LODASH), osv(found).join('\n'))
})

test('grype-silenced: the settings of the target have no effect on Grype', { skip }, async () => {
  const found = await run(fixture('grype-silenced'))
  assert.ok(grype(found).includes(LODASH_GRYPE), grype(found).join('\n'))
})

test('clean: Grype has nothing to check', { skip }, async () => {
  const found = await run(fixture('clean'))
  assert.deepEqual(found.steps.find((entry) => entry.id === 'grype').count, 0)
})

test('dev-npm: a dev package is in the SBOM, and its flaw blocks in both tools', { skip }, async () => {
  const found = await run(fixture('dev-npm'))
  assert.ok(sbom(found).includes('pkg:npm/lodash@4.17.15'), sbom(found).join('\n'))
  assert.ok(grype(found).includes(LODASH_GRYPE), grype(found).join('\n'))
  assert.ok(osv(found).includes(LODASH), osv(found).join('\n'))
  assert.equal(found.verdict, 'bloqué')
})
