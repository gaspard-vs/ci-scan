// The runner and the gate, with steps that the test plays itself. No Docker.
import assert from 'node:assert/strict'
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { annotations, text } from '../report.mjs'
import { run } from '../run.mjs'
import { readStages } from '../steps.mjs'

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

// Plays the steps: `answers` gives the result of each step, by its id.
function play(answers, started = []) {
  return async (step) => {
    started.push(step.id)
    const answer = answers[step.id]
    if (!answer) throw new Error(`unexpected step ${step.id}`)
    return answer
  }
}

const rules = (found) => found.findings.filter((finding) => finding.blocks).map((finding) => finding.rule ?? finding.title)

test('a clean repository passes', async () => {
  const found = await run(fixture('clean'), {
    launch: play({ detection: ok(lines(CLEAN)), gitleaks: ok(sarif()) }),
  })
  assert.equal(found.verdict, 'conforme')
  assert.deepEqual(found.findings, [])
  assert.deepEqual(found.steps, [{ id: 'gitleaks', control: 'Secrets', count: 0 }])
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

test('a stage that gives no SARIF blocks', async () => {
  for (const answer of [ok('8.30.1\n'), ok('{"version":"2.1.0"}'), ok('')]) {
    const found = await run(fixture('clean'), { launch: play({ detection: ok(lines(CLEAN)), gitleaks: answer }) })
    assert.equal(found.verdict, 'bloqué')
    assert.deepEqual(rules(found), ['step-failed'])
    assert.equal(found.steps[0].count, null)
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
  assert.deepEqual(started, ['detection', 'gitleaks'])
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
  const detection = [...CLEAN.slice(1), file('README.md', 'Python'), file('pixel.png', 'Python')]
  const found = await run(fixture('clean'), { launch: play({ detection: ok(lines(detection)), gitleaks: ok(sarif()) }) })
  assert.deepEqual(rules(found), ['uncovered-technology'])
  assert.equal(found.findings[0].title, 'Technologie non couverte : Python (2 fichiers)')
  assert.deepEqual(found.uncovered, ['Python'])
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
  assert.deepEqual(started, ['detection', 'gitleaks', 'lint'])

  // Without a Python file, the stage of Python does not run.
  started.length = 0
  await run(fixture('clean'), { techDir, launch: play({ ...answers, detection: ok(lines(CLEAN)) }, started) })
  assert.deepEqual(started, ['detection', 'gitleaks'])
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
