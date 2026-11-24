// The runner and the gate, with steps that the test plays itself. No Docker.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readdir, readFile, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { annotations, text } from '../report.mjs'
import { run as runner } from '../run.mjs'
import { nameMatches, readStages, readTechnologies } from '../steps.mjs'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const fixture = (name) => path.join(ROOT, 'fixtures', name)

const ok = (stdout) => ({ code: 0, stdout, stderr: '' })
const lines = (entries) => entries.map((entry) => JSON.stringify(entry)).join('\n')
const file = (name, language) => ({ path: name, language, binary: false, mime: 'text/plain', link: false })

function sarif(results = [], rules = []) {
  return JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'fake', rules } }, results }] })
}

function result(ruleId, name, line) {
  return {
    ruleId,
    locations: [
      { physicalLocation: { artifactLocation: { uri: `/scan/repo/${name}` }, region: { startLine: line } } },
    ],
  }
}

// The detection of the fixture `clean`, as the container gives it.
const CLEAN = [
  file('README.md', 'Markdown'),
  file('config.properties', 'Java Properties'),
  file('settings.yaml', 'YAML'),
  { path: 'pixel.png', language: '', binary: true, mime: 'image/png', link: false },
]

// An empty SBOM, as the Syft stage gives it.
const SBOM = JSON.stringify({
  version: '2.1.0',
  runs: [{ tool: { driver: { name: 'syft' } }, results: [], properties: {
    'ci-scan/output': { name: 'sbom.cdx.json', content: { bomFormat: 'CycloneDX', components: [] } },
  } }],
})

// Plays the steps: `answers` gives the result of each step, by its id. A
// stage with no answer gives no result; Syft gives an empty SBOM. A
// preparation of data is not counted, and works.
function play(answers, started = []) {
  return async (step, _repo, options = {}) => {
    if (options.prepareDir) return ok('')
    started.push(step.id)
    const answer = answers[step.id] ?? (step.id === 'syft' ? ok(SBOM) : step.gravity ? ok(sarif()) : undefined)
    if (!answer) throw new Error(`unexpected step ${step.id}`)
    return answer
  }
}

// The data of the stages of CI scan, from a fake server: no network.
const ARCHIVE = Buffer.from('a database')
async function fakeData(url) {
  if (url.endsWith('/latest.json')) {
    const checksum = `sha256:${createHash('sha256').update(ARCHIVE).digest('hex')}`
    return Response.json({ path: 'db.tar.zst', checksum, built: '2026-11-18T06:00:00Z' })
  }
  if (url.endsWith('/db.tar.zst')) return new Response(ARCHIVE)
  throw new Error(`no network in the tests: ${url}`)
}
const testCache = await mkdtemp(path.join(os.tmpdir(), 'ci-scan-cache-'))

// The runner, with the fake data unless the test gives its own.
const run = (target, options = {}) => runner(target, { fetch: fakeData, cacheDir: testCache, ...options })

const rules = (found) => found.findings.filter((finding) => finding.blocks).map((finding) => finding.rule ?? finding.title)

test('a clean repository passes', async () => {
  const found = await run(fixture('clean'), {
    launch: play({ detection: ok(lines(CLEAN)), gitleaks: ok(sarif()) }),
  })
  assert.equal(found.verdict, 'conforme')
  assert.deepEqual(found.findings, [])
  assert.deepEqual(found.steps, [
    { id: 'syft', control: 'Inventaire des composants', count: 0, outputs: ['sbom.cdx.json'] },
    { id: 'gitleaks', control: 'Secrets', count: 0 },
    { id: 'opengrep', control: 'Analyse du code', count: 0 },
    { id: 'osv', control: 'Vulnérabilités connues', count: 0 },
    // No pom.xml: the Maven stage does not run.
    { id: 'osv-maven', control: 'Vulnérabilités connues', count: 0 },
    { id: 'grype', control: 'Vulnérabilités connues', count: 0, data: [{ file: 'grype/vulnerability-db.tar.zst', date: '2026-11-18T06:00:00.000Z' }] },
  ])
})

test('a result of a stage blocks, with its file and its line', async () => {
  const found = await run(fixture('clean'), {
    launch: play({ detection: ok(lines(CLEAN)), gitleaks: ok(sarif([result('generic-api-key', 'config.properties', 3)])) }),
  })
  assert.equal(found.verdict, 'bloqué')
  const [finding] = found.findings
  assert.deepEqual(
    { title: finding.title, file: finding.file, line: finding.line, control: finding.control },
    { title: 'generic-api-key', file: 'config.properties', line: 3, control: 'Secrets' },
  )
  assert.match(text(found), /\[Secrets\] config\.properties:3 — generic-api-key/)
  assert.equal(annotations(found), '::error file=config.properties,line=3::[Secrets] generic-api-key')
})

test('a medium result is reported and does not block', async () => {
  const medium = [{ id: 'weak', properties: { 'security-severity': '5.0' } }]
  const found = await run(fixture('clean'), {
    launch: play({ detection: ok(lines(CLEAN)), gitleaks: ok(sarif([result('weak', 'settings.yaml', 1)], medium)) }),
  })
  assert.equal(found.verdict, 'conforme')
  assert.equal(found.findings[0].gravity, 'medium')
  assert.match(text(found), /Signalé :/)
})

test('the gravity of a rule can be a word', async () => {
  const words = [
    { id: 'a', properties: { 'security-severity': 'HIGH' } },
    { id: 'b', properties: { 'security-severity': 'Medium' } },
    { id: 'c', properties: { 'security-severity': 'Info' } },
    { id: 'd', properties: { 'security-severity': 'unknown' } },
  ]
  const results = ['a', 'b', 'c', 'd'].map((id) => result(id, 'settings.yaml', 1))
  const found = await run(fixture('clean'), {
    launch: play({ detection: ok(lines(CLEAN)), gitleaks: ok(sarif(results, words)) }),
  })
  // An unknown word gives the gravity of the stage.
  assert.deepEqual(found.findings.map((finding) => finding.gravity), ['high', 'medium', 'low', 'high'])
})

test('the gravity that the stage sets for a rule comes first', async () => {
  const commonDir = await mkdtemp(path.join(os.tmpdir(), 'ci-scan-stages-'))
  await mkdir(path.join(commonDir, '10-set'))
  const stage = {
    id: 'set', control: 'Essai', image: `x@sha256:${'0'.repeat(64)}`, args: [], gravity: 'low',
    gravities: { raised: 'high' },
  }
  await writeFile(path.join(commonDir, '10-set', 'stage.json'), JSON.stringify(stage))
  const severity = [{ id: 'raised', properties: { 'security-severity': 'Medium' } }]
  const results = [result('raised', 'settings.yaml', 1), result('other', 'settings.yaml', 2)]
  const found = await run(fixture('clean'), {
    commonDir,
    detectionDir: path.join(ROOT, 'common', 'detection'),
    launch: play({ detection: ok(lines(CLEAN)), set: ok(sarif(results, severity)) }),
  })
  assert.deepEqual(found.findings.map((finding) => finding.gravity), ['high', 'low'])
  assert.equal(found.verdict, 'bloqué')
})

test('"tmp" and "gravities" of a stage are checked', async () => {
  const base = { id: 'bad', control: 'Essai', image: `x@sha256:${'0'.repeat(64)}`, args: [], gravity: 'high' }
  for (const [extra, message] of [
    [{ tmp: 'yes' }, /"tmp" must be true or false/],
    [{ gravities: { rule: 'severe' } }, /"gravities" must give one of/],
    [{ gravities: ['high'] }, /"gravities" must give one of/],
  ]) {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'ci-scan-stages-'))
    await mkdir(path.join(dir, '10-bad'))
    await writeFile(path.join(dir, '10-bad', 'stage.json'), JSON.stringify({ ...base, ...extra }))
    await assert.rejects(readStages(dir), message)
  }
})

test('a stage that gives no SARIF blocks', async () => {
  for (const answer of [ok('8.30.1\n'), ok('{"version":"2.1.0"}'), ok('')]) {
    const found = await run(fixture('clean'), { launch: play({ detection: ok(lines(CLEAN)), gitleaks: answer }) })
    assert.equal(found.verdict, 'bloqué')
    assert.deepEqual(rules(found), ['step-failed'])
    assert.equal(found.steps.find((step) => step.id === 'gitleaks').count, null)
  }
})

test('a stage that ends with an error blocks, also with a valid result', async () => {
  const found = await run(fixture('clean'), {
    launch: play({ detection: ok(lines(CLEAN)), gitleaks: { code: 1, stdout: sarif(), stderr: 'boom' } }),
  })
  assert.equal(found.verdict, 'bloqué')
  assert.match(found.findings[0].title, /« gitleaks » n'a pas pu tourner : boom/)
})

test('a stage that does not start or is killed blocks', async () => {
  const found = await run(fixture('clean'), {
    launch: play({ detection: ok(lines(CLEAN)), gitleaks: { code: null, stdout: '', stderr: 'timeout' } }),
  })
  assert.deepEqual(rules(found), ['step-failed'])
})

test('a detection that fails blocks, and the stages still run', async () => {
  const started = []
  const found = await run(fixture('clean'), {
    launch: play({ detection: { code: 1, stdout: '', stderr: 'no image' }, gitleaks: ok(sarif()) }, started),
  })
  assert.deepEqual(rules(found), ['step-failed'])
  assert.deepEqual(started, ['detection', 'syft', 'gitleaks', 'opengrep', 'osv', 'grype'])
})

test('a detection that is not readable blocks', async () => {
  const found = await run(fixture('clean'), { launch: play({ detection: ok('not json'), gitleaks: ok(sarif()) }) })
  assert.deepEqual(rules(found), ['step-failed'])
})

test('a file that the detection does not name has no owner', async () => {
  const found = await run(fixture('clean'), {
    launch: play({ detection: ok(lines(CLEAN.slice(1))), gitleaks: ok(sarif()) }),
  })
  assert.equal(found.verdict, 'bloqué')
  assert.deepEqual(rules(found), ['unowned-file'])
  assert.equal(found.findings[0].file, 'README.md')
})

test('a technology that CI scan does not cover blocks, once for each language', async () => {
  const detection = [...CLEAN.slice(1), file('README.md', 'Rust'), file('pixel.png', 'Rust')]
  const found = await run(fixture('clean'), { launch: play({ detection: ok(lines(detection)), gitleaks: ok(sarif()) }) })
  assert.deepEqual(rules(found), ['uncovered-technology'])
  assert.equal(found.findings[0].title, 'Technologie non couverte : Rust (2 fichiers)')
  assert.deepEqual(found.uncovered, ['Rust'])
})

// The kinds of files found in the BPE projects on 2026-11-19. Each has one
// owner: a technology, a configuration kind or a kind without risk.
const BPE_KINDS = {
  Java: 'java', 'Maven POM': 'java',
  JavaScript: 'javascript', TypeScript: 'javascript', HTML: 'javascript', CSS: 'javascript', SCSS: 'javascript',
  Shell: 'shell', Batchfile: 'shell', Dockerfile: 'docker', Python: 'python', SQL: 'sql',
  XML: 'configuration', 'JSON with Comments': 'configuration', Browserslist: 'configuration',
  Gherkin: 'inert', SVG: 'inert',
}

test('each kind of file of the BPE projects has one owner', async () => {
  const technologies = await readTechnologies(path.join(ROOT, 'tech'))
  const policy = JSON.parse(await readFile(path.join(ROOT, 'policy', 'owners.json'), 'utf8'))
  for (const [language, expected] of Object.entries(BPE_KINDS)) {
    const owners = technologies.filter((tech) => tech.languages.includes(language)).map((tech) => tech.name)
    if (policy.configuration.languages.includes(language)) owners.push('configuration')
    if (policy.inert.languages.includes(language)) owners.push('inert')
    assert.deepEqual(owners, [expected], language)
  }
})

test('an empty file, .nvmrc and .env-sample have an owner; .env and a full .gitkeep do not', async () => {
  const repo = await mkdtemp(path.join(os.tmpdir(), 'ci-scan-names-'))
  const content = {
    'assets/.gitkeep': '',
    'full/.gitkeep': 'not empty\n',
    '.nvmrc': '22\n',
    '.env-sample': 'DB_HOST=\n',
    '.env': 'DB_HOST=db\n',
  }
  for (const [name, text] of Object.entries(content)) {
    await mkdir(path.dirname(path.join(repo, name)), { recursive: true })
    await writeFile(path.join(repo, name), text)
  }
  const detection = Object.keys(content).map((name) => file(name, ''))
  const found = await run(repo, { launch: play({ detection: ok(lines(detection)), gitleaks: ok(sarif()) }) })
  assert.deepEqual(
    found.findings.map((finding) => finding.file).sort(),
    ['.env', 'full/.gitkeep'],
  )
})

test('a language with two technologies is refused', async () => {
  const techDir = await mkdtemp(path.join(os.tmpdir(), 'ci-scan-tech-'))
  for (const name of ['one', 'two']) {
    await mkdir(path.join(techDir, name))
    await writeFile(path.join(techDir, name, 'tech.json'), JSON.stringify({ languages: ['Rust'] }))
  }
  await assert.rejects(readTechnologies(techDir), /Rust is already owned by one/)
})

test('a technology with no stage of its own has the common stages only, and the report says so', async () => {
  const techDir = await mkdtemp(path.join(os.tmpdir(), 'ci-scan-tech-'))
  await mkdir(path.join(techDir, 'rust'))
  await writeFile(path.join(techDir, 'rust', 'tech.json'), JSON.stringify({ name: 'Rust', languages: ['Rust'] }))
  const started = []
  const detection = [...CLEAN.slice(1), file('README.md', 'Rust')]
  const found = await run(fixture('clean'), {
    techDir,
    launch: play({ detection: ok(lines(detection)), gitleaks: ok(sarif()) }, started),
  })
  assert.equal(found.verdict, 'conforme')
  assert.deepEqual(found.coverage, [{ name: 'rust', label: 'Rust', commonOnly: true }])
  assert.deepEqual(started, ['detection', 'syft', 'gitleaks', 'opengrep', 'osv', 'grype'])
  assert.match(text(found), /^Technologies couvertes : Rust \(contrôles communs seulement\)$/m)
})

test('a symbolic link, an unknown text and an unknown binary have no owner', async () => {
  const detection = [
    { path: 'README.md', link: true },
    file('config.properties', ''),
    { path: 'pixel.png', language: '', binary: true, mime: 'application/octet-stream', link: false },
    file('settings.yaml', 'YAML'),
  ]
  const found = await run(fixture('clean'), { launch: play({ detection: ok(lines(detection)), gitleaks: ok(sarif()) }) })
  assert.deepEqual(
    found.findings.map((finding) => finding.title),
    [
      'Fichier sans propriétaire : lien symbolique',
      'Fichier sans propriétaire : type de fichier inconnu',
      'Fichier sans propriétaire : binaire de type inconnu',
    ],
  )
})

test('a text file with the name of an image is not inert', async () => {
  const detection = [...CLEAN.slice(0, 3), { path: 'pixel.png', language: '', binary: false, mime: 'image/png', link: false }]
  const found = await run(fixture('clean'), { launch: play({ detection: ok(lines(detection)), gitleaks: ok(sarif()) }) })
  assert.deepEqual(rules(found), ['unowned-file'])
})

test('a covered technology owns its files and adds its stages', async () => {
  const techDir = await mkdtemp(path.join(os.tmpdir(), 'ci-scan-tech-'))
  const stageDir = path.join(techDir, 'python', '10-lint')
  await mkdir(stageDir, { recursive: true })
  await writeFile(path.join(techDir, 'python', 'tech.json'), JSON.stringify({ languages: ['Python'] }))
  await writeFile(
    path.join(stageDir, 'stage.json'),
    JSON.stringify({ id: 'lint', control: 'Analyse du code', image: `x@sha256:${'0'.repeat(64)}`, args: [], gravity: 'high' }),
  )
  const started = []
  const detection = [...CLEAN.slice(1), file('README.md', 'Python')]
  const answers = { detection: ok(lines(detection)), gitleaks: ok(sarif()), lint: ok(sarif()) }
  const found = await run(fixture('clean'), { techDir, launch: play(answers, started) })
  assert.equal(found.verdict, 'conforme')
  assert.deepEqual(found.technologies, ['python'])
  assert.deepEqual(started, ['detection', 'syft', 'gitleaks', 'opengrep', 'osv', 'grype', 'lint'])

  // Without a Python file, the stage of Python does not run.
  started.length = 0
  await run(fixture('clean'), { techDir, launch: play({ ...answers, detection: ok(lines(CLEAN)) }, started) })
  assert.deepEqual(started, ['detection', 'syft', 'gitleaks', 'opengrep', 'osv', 'grype'])
})

test('a stage must fix its image by digest', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'ci-scan-stages-'))
  await mkdir(path.join(dir, '10-loose'))
  const stage = { id: 'loose', control: 'Essai', image: 'ghcr.io/gitleaks/gitleaks:latest', args: [], gravity: 'high' }
  await writeFile(path.join(dir, '10-loose', 'stage.json'), JSON.stringify(stage))
  await assert.rejects(readStages(dir), /must end with its sha256 digest/)
})

test('an annotation cannot be forged by a file name', async () => {
  const found = await run(fixture('clean'), {
    launch: play({ detection: ok(lines(CLEAN)), gitleaks: ok(sarif([result('rule', 'a,b:c\nd', 2)])) }),
  })
  assert.equal(annotations(found), '::error file=a%2Cb%3Ac%0Ad,line=2::[Secrets] rule')
})

// A folder of stages with one stage, for the tests below.
async function oneStage(extra) {
  const commonDir = await mkdtemp(path.join(os.tmpdir(), 'ci-scan-stages-'))
  await mkdir(path.join(commonDir, '10-one'))
  const stage = { id: 'one', control: 'Essai', image: `x@sha256:${'0'.repeat(64)}`, args: [], gravity: 'high', ...extra }
  await writeFile(path.join(commonDir, '10-one', 'stage.json'), JSON.stringify(stage))
  return { commonDir, detectionDir: path.join(ROOT, 'common', 'detection') }
}

test('"env", "files", "data", "proxy" and "build" of a stage are checked', async () => {
  const data = { file: 'db/all.zip', url: 'https://example.org/all.zip', when: ['package-lock.json'] }
  for (const [extra, message] of [
    [{ env: { lower: 'x' } }, /"env" must give a text for each NAME/],
    [{ env: { NAME: 1 } }, /"env" must give a text for each NAME/],
    [{ files: [] }, /"files" must be a list of file name patterns/],
    [{ files: ['a/pom.xml'] }, /"files" must be a list of file name patterns/],
    [{ data: [{ ...data, url: 'http://example.org/all.zip' }] }, /"data" must give/],
    [{ data: [{ ...data, file: '../all.zip' }] }, /"data" must give/],
    [{ data: [{ ...data, when: [] }] }, /"data" must give/],
    [{ proxy: { build: '/abs', args: [] } }, /"proxy" must give/],
    [{ proxy: { build: 'helper', args: [] }, network: true }, /"network" or "proxy", not both/],
    [{ image: undefined, build: '' }, /give "image" or "build"/],
    [{ build: 'other' }, /give "image" or "build"/],
    [{ data: [{ ...data, listing: 'https://example.org/latest.json' }] }, /"data" must give/],
    [{ data: [{ file: 'db', listing: 'http://example.org/latest.json', when: ['*'] }] }, /"data" must give/],
    [{ input: '../sbom.json' }, /"input" must be the short name/],
    [{ input: 'out/sbom.json' }, /"input" must be the short name/],
    [{ prepare: { folder: 'db', args: [] } }, /"prepare" must give/],
    [{ data: [data], prepare: { folder: '../db', args: [] } }, /"prepare" must give/],
    [{ data: [data], prepare: { folder: 'db' } }, /"prepare" must give/],
  ]) {
    const { commonDir } = await oneStage(extra)
    await assert.rejects(readStages(commonDir), message, JSON.stringify(extra))
  }
  const { commonDir } = await oneStage({ image: undefined, build: '../other', env: { A_B: 'x' }, files: ['*.xml'], data: [data] })
  assert.equal((await readStages(commonDir)).length, 1)
  const listed = { file: 'db', listing: 'https://example.org/latest.json', when: ['*'] }
  const other = await oneStage({ data: [listed], prepare: { folder: 'db-ready', args: ['prepare'] }, input: 'sbom.cdx.json' })
  assert.equal((await readStages(other.commonDir)).length, 1)
})

test('a file name pattern applies to the name of the file', () => {
  assert.ok(nameMatches('a/b/pom.xml', 'pom.xml'))
  assert.ok(nameMatches('requirements-dev.txt', 'requirements*.txt'))
  assert.ok(!nameMatches('pom.xml.bak', 'pom.xml'))
  assert.ok(!nameMatches('pomXxml', 'pom.xml'))
})

test('a stage with "files" sees only copies of these files, and does not run without them', async () => {
  const repo = await mkdtemp(path.join(os.tmpdir(), 'ci-scan-repo-'))
  await mkdir(path.join(repo, 'api'))
  await writeFile(path.join(repo, 'pom.xml'), '<project/>')
  await writeFile(path.join(repo, 'api', 'pom.xml'), '<project/>')
  await writeFile(path.join(repo, 'README.md'), 'hello')
  const detection = [file('pom.xml', 'XML'), file('api/pom.xml', 'XML'), file('README.md', 'Markdown')]
  const options = await oneStage({ files: ['pom.xml'] })
  let seen = null
  const launch = async (step, dir) => {
    if (step.id === 'detection') return ok(lines(detection))
    seen = (await readdir(dir, { recursive: true })).sort()
    return ok(sarif())
  }
  await run(repo, { ...options, launch })
  assert.deepEqual(seen, ['api', 'api/pom.xml', 'pom.xml'])

  const started = []
  const found = await run(fixture('clean'), { ...options, launch: play({ detection: ok(lines(CLEAN)) }, started) })
  assert.deepEqual(started, ['detection'])
  assert.deepEqual(found.steps, [{ id: 'one', control: 'Essai', count: 0 }])
})

test('a stage gets its data at /data, and the report gives its date', async () => {
  const cacheDir = await mkdtemp(path.join(os.tmpdir(), 'ci-scan-cache-'))
  const body = Buffer.from('the database')
  const md5 = createHash('md5').update(body).digest('base64')
  const headers = { 'x-goog-hash': `crc32c=AAAA, md5=${md5}`, 'last-modified': 'Wed, 18 Nov 2026 13:03:03 GMT' }
  const fetch = async (_url, init) => new Response(init?.method === 'HEAD' ? null : body, { headers })
  const options = await oneStage({ data: [{ file: 'db/all.zip', url: 'https://example.org/all.zip', when: ['*.properties'] }] })
  let dataDir = null
  const launch = async (step, _repo, opts) => {
    if (step.id === 'detection') return ok(lines(CLEAN))
    dataDir = opts.dataDir
    return ok(sarif())
  }
  const found = await run(fixture('clean'), { ...options, launch, cacheDir, fetch })
  assert.equal(await readFile(path.join(dataDir, 'db', 'all.zip'), 'utf8'), 'the database')
  assert.deepEqual(found.steps[0].data, [{ file: 'db/all.zip', date: '2026-11-18T13:03:03.000Z' }])
  assert.match(text(found), /données : db\/all\.zip, du 2026-11-18 13:03 UTC/)
  assert.deepEqual(found.sarif.runs[1].properties['ci-scan/data'], found.steps[0].data)
})

test('data that cannot be had blocks the stage', async () => {
  const cacheDir = await mkdtemp(path.join(os.tmpdir(), 'ci-scan-cache-'))
  const fetch = async () => new Response(null, { status: 503 })
  const options = await oneStage({ data: [{ file: 'all.zip', url: 'https://example.org/all.zip', when: ['*.properties'] }] })
  const started = []
  const found = await run(fixture('clean'), { ...options, cacheDir, fetch, launch: play({ detection: ok(lines(CLEAN)) }, started) })
  assert.deepEqual(started, ['detection'])
  assert.deepEqual(rules(found), ['step-failed'])
  assert.match(found.findings[0].title, /données : https:\/\/example\.org\/all\.zip: HTTP 503/)
})

test('a result for information is listed, is not counted and does not block', async () => {
  const note = {
    ruleId: 'internal-package',
    kind: 'informational',
    level: 'none',
    message: { text: 'Paquet interne, non vérifié ici : ch.vs.a:b@1' },
    locations: [{ physicalLocation: { artifactLocation: { uri: '/scan/repo/pom.xml' } } }],
  }
  const options = await oneStage({})
  const found = await run(fixture('clean'), { ...options, launch: play({ detection: ok(lines(CLEAN)), one: ok(sarif([note])) }) })
  assert.equal(found.verdict, 'conforme')
  assert.deepEqual(found.findings, [])
  assert.equal(found.steps[0].count, 0)
  assert.deepEqual(found.notes.map((n) => `${n.file}: ${n.title}`), ['pom.xml: Paquet interne, non vérifié ici : ch.vs.a:b@1'])
  assert.match(text(found), /Pour information :\n {2}\[Essai\] pom\.xml — Paquet interne/)
})

test('the requests of a proxy are counted in the report and kept in the SARIF', async () => {
  const requests = [
    { method: 'GET', path: '/maven2/a/b/1/b-1.pom', action: 'forward', status: 200 },
    { method: 'POST', path: '/x', action: 'refused', status: 403 },
  ]
  const options = await oneStage({})
  const found = await run(fixture('clean'), {
    ...options,
    launch: play({ detection: ok(lines(CLEAN)), one: { ...ok(sarif()), requests } }),
  })
  assert.deepEqual(found.steps[0].requests, { total: 2, refused: 1 })
  assert.match(text(found), /requêtes vers l'extérieur : 2, dont 1 refusée\(s\)/)
  assert.deepEqual(found.sarif.runs[1].properties['ci-scan/requests'], requests)
})

// A SARIF with no result that gives a file and a summary line.
function giving(name, content, summary) {
  const properties = { 'ci-scan/output': { name, content } }
  if (summary !== undefined) properties['ci-scan/summary'] = summary
  return JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'fake' } }, results: [], properties }] })
}

test('a stage can give a file and a summary line, which leave the SARIF', async () => {
  const sbom = { bomFormat: 'CycloneDX', components: [] }
  const options = await oneStage({})
  const found = await run(fixture('clean'), {
    ...options,
    launch: play({ detection: ok(lines(CLEAN)), one: ok(giving('sbom.cdx.json', sbom, '0 composant')) }),
  })
  assert.equal(found.verdict, 'conforme')
  assert.deepEqual(found.outputs, [{ name: 'sbom.cdx.json', content: sbom }])
  assert.deepEqual(found.steps[0], { id: 'one', control: 'Essai', count: 0, summary: '0 composant', outputs: ['sbom.cdx.json'] })
  assert.match(text(found), /one \(Essai\) : 0 résultat\(s\)\n {4}0 composant\n {4}fichier : sbom\.cdx\.json/)
  assert.deepEqual(found.sarif.runs[1].properties, { 'ci-scan/summary': '0 composant' })
})

test('a file with a path, or a summary on two lines, blocks the stage', async () => {
  for (const answer of [
    giving('../sbom.json', {}),
    giving('out/sbom.json', {}),
    giving('Sbom.json', {}),
    giving('sbom.json', undefined),
    giving('sbom.json', {}, 'a\nb'),
  ]) {
    const options = await oneStage({})
    const found = await run(fixture('clean'), { ...options, launch: play({ detection: ok(lines(CLEAN)), one: ok(answer) }) })
    assert.deepEqual(rules(found), ['step-failed'], answer)
    assert.deepEqual(found.outputs, [])
  }
})

test('two stages cannot give the same file', async () => {
  const options = await oneStage({})
  await mkdir(path.join(options.commonDir, '20-two'))
  const two = { id: 'two', control: 'Essai', image: `x@sha256:${'0'.repeat(64)}`, args: [], gravity: 'high' }
  await writeFile(path.join(options.commonDir, '20-two', 'stage.json'), JSON.stringify(two))
  const found = await run(fixture('clean'), {
    ...options,
    launch: play({ detection: ok(lines(CLEAN)), one: ok(giving('sbom.json', { a: 1 })), two: ok(giving('sbom.json', { a: 2 })) }),
  })
  assert.deepEqual(rules(found), ['step-failed'])
  assert.match(found.findings[0].title, /« two ».*a stage already gives sbom\.json/)
  assert.deepEqual(found.outputs, [{ name: 'sbom.json', content: { a: 1 } }])
})

// Two stages: "one" gives a file, "two" reads it.
async function twoStages(two) {
  const options = await oneStage({})
  await mkdir(path.join(options.commonDir, '20-two'))
  const stage = { id: 'two', control: 'Essai', image: `x@sha256:${'0'.repeat(64)}`, args: [], gravity: 'high', ...two }
  await writeFile(path.join(options.commonDir, '20-two', 'stage.json'), JSON.stringify(stage))
  return options
}

test('a stage reads the file of an earlier stage at /input, alone', async () => {
  const sbom = { bomFormat: 'CycloneDX', components: [{ name: 'a' }] }
  const options = await twoStages({ input: 'sbom.cdx.json' })
  let seen = null
  const launch = async (step, _repo, opts) => {
    if (step.id === 'detection') return ok(lines(CLEAN))
    if (step.id === 'one') return ok(giving('sbom.cdx.json', sbom))
    seen = { files: await readdir(opts.inputDir), content: JSON.parse(await readFile(path.join(opts.inputDir, 'sbom.cdx.json'), 'utf8')) }
    return ok(sarif())
  }
  const found = await run(fixture('clean'), { ...options, launch })
  assert.deepEqual(seen, { files: ['sbom.cdx.json'], content: sbom })
  assert.equal(found.verdict, 'conforme')
})

test('a stage without its input does not run, and blocks', async () => {
  const options = await twoStages({ input: 'sbom.cdx.json' })
  const started = []
  const found = await run(fixture('clean'), {
    ...options,
    launch: play({ detection: ok(lines(CLEAN)), one: { code: 1, stdout: '', stderr: 'syft failed' } }, started),
  })
  assert.deepEqual(started, ['detection', 'one'])
  assert.deepEqual(rules(found), ['step-failed', 'step-failed'])
  assert.match(found.findings[1].title, /« two ».*entrée : aucune étape avant elle ne donne sbom\.cdx\.json/)
})

// A stage with data from a listing, prepared once a day.
async function preparedStage(cacheDir) {
  const body = Buffer.from('the archive')
  const checksum = `sha256:${createHash('sha256').update(body).digest('hex')}`
  const fetch = async (url) =>
    url.endsWith('latest.json') ? Response.json({ path: 'db.tar.zst', checksum, built: '2026-11-18T06:00:00Z' }) : new Response(body)
  const options = await oneStage({
    data: [{ file: 'db.tar.zst', listing: 'https://example.org/latest.json', when: ['*'] }],
    prepare: { folder: 'db-ready', args: ['prepare'] },
    args: ['scan'],
  })
  return { ...options, cacheDir, fetch }
}

test('the data of a stage is prepared once, then read by each scan', async () => {
  const cacheDir = await mkdtemp(path.join(os.tmpdir(), 'ci-scan-cache-'))
  const options = await preparedStage(cacheDir)
  const calls = []
  const launch = async (step, repo, opts) => {
    if (step.id === 'detection') return ok(lines(CLEAN))
    if (opts.prepareDir) {
      calls.push({ prepare: path.basename(opts.prepareDir), repo, input: opts.inputDir, data: await readdir(opts.dataDir) })
      await writeFile(path.join(opts.prepareDir, 'db'), 'ready')
      return ok('')
    }
    calls.push({ scan: await readFile(path.join(opts.dataDir, 'db-ready', 'db'), 'utf8') })
    return ok(sarif())
  }
  const first = await run(fixture('clean'), { ...options, launch })
  await run(fixture('clean'), { ...options, launch })
  assert.deepEqual(calls, [
    { prepare: 'db-ready', repo: null, input: undefined, data: ['db-ready', 'db.tar.zst'] },
    { scan: 'ready' },
    { scan: 'ready' },
  ])
  assert.equal(first.verdict, 'conforme')
})

test('a failed preparation blocks the stage, leaves no folder, and runs again on the next scan', async () => {
  const cacheDir = await mkdtemp(path.join(os.tmpdir(), 'ci-scan-cache-'))
  const options = await preparedStage(cacheDir)
  let prepared = 0
  const launch = async (step, _repo, opts) => {
    if (step.id === 'detection') return ok(lines(CLEAN))
    if (opts.prepareDir) {
      prepared += 1
      await writeFile(path.join(opts.prepareDir, 'half'), 'x')
      return { code: 2, stdout: '', stderr: 'grype db import: bad archive' }
    }
    throw new Error('the stage must not run')
  }
  const found = await run(fixture('clean'), { ...options, launch })
  assert.deepEqual(rules(found), ['step-failed'])
  assert.match(found.findings[0].title, /préparation des données : grype db import: bad archive/)
  const day = path.join(cacheDir, 'data', (await readdir(path.join(cacheDir, 'data')))[0])
  assert.deepEqual(await readdir(day), ['db.tar.zst'])
  await run(fixture('clean'), { ...options, launch })
  assert.equal(prepared, 2)
})

test('a prepared folder made from other data is prepared again', async () => {
  const cacheDir = await mkdtemp(path.join(os.tmpdir(), 'ci-scan-cache-'))
  const options = await preparedStage(cacheDir)
  let prepared = 0
  const launch = async (step, _repo, opts) => {
    if (step.id === 'detection') return ok(lines(CLEAN))
    if (opts.prepareDir) prepared += 1
    return ok(opts.prepareDir ? '' : sarif())
  }
  await run(fixture('clean'), { ...options, launch })
  const day = path.join(cacheDir, 'data', (await readdir(path.join(cacheDir, 'data')))[0])
  await writeFile(path.join(day, 'db-ready.ready'), '{"image":"other"}')
  await run(fixture('clean'), { ...options, launch })
  assert.equal(prepared, 2)
})
