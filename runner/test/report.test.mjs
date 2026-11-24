// The report for people, rapport.md, from results that the test writes itself.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { MAX_ROWS, markdown } from '../report.mjs'

const STEPS = [
  { id: 'syft', control: 'Inventaire des composants', count: 0, summary: '2 composants', outputs: ['sbom.cdx.json'], requests: { total: 3, refused: 0 } },
  { id: 'grype', control: 'Vulnérabilités connues', count: 1, data: [{ file: 'grype/db.tar.zst', date: '2026-11-24T06:22:00Z' }] },
  { id: 'opengrep', control: 'Analyse du code', count: null },
]

const result = (findings, more = {}) => ({
  repo: '/tmp/target',
  files: 12,
  technologies: ['java'],
  coverage: [{ name: 'java', label: 'Java', commonOnly: true }],
  uncovered: [],
  steps: STEPS,
  findings,
  notes: [],
  verdict: findings.some((finding) => finding.blocks) ? 'bloqué' : 'conforme',
  ...more,
})

const section = (text, title) => text.split(`## ${title}\n`)[1]?.split('\n## ')[0]

test('a clean result: the decision, the technologies and the steps', () => {
  const text = markdown(result([]), { name: 'gaspard-vs/ci-scan-test', date: new Date('2026-11-24T14:05:30Z') })
  assert.match(text, /^# CI scan : gaspard-vs\/ci-scan-test$/m)
  assert.match(text, /^Scan du 2026-11-24 14:05 UTC\.$/m)
  assert.match(text, /^\*\*Décision : conforme\*\*$/m)
  assert.match(section(text, 'Technologies'), /^\| Java \| Couverte : contrôles communs seulement \|$/m)
  assert.equal(section(text, 'Résultats'), undefined)
  assert.equal(section(text, 'Points bloquants'), undefined)
  const steps = section(text, 'Étapes')
  assert.match(steps, /^\| Inventaire des composants \(syft\) \| 0 \| 2 composants ; fichier `sbom.cdx.json` ; 3 requête\(s\) vers l'extérieur, 0 refusée\(s\) \|$/m)
  assert.match(steps, /^\| Vulnérabilités connues \(grype\) \| 1 \| données du 2026-11-24 06:22 UTC \|$/m)
  assert.match(steps, /^\| Analyse du code \(opengrep\) \| N'a pas pu tourner \|  \|$/m)
})

test('a blocked result: the counts, the blocking points, the reported ones and the notes', () => {
  const findings = [
    { source: 'osv', control: 'Vulnérabilités connues', gravity: 'critical', title: 'lodash@4.17.21 CVE-2026-4800', file: 'package-lock.json', blocks: true },
    { source: 'opengrep', control: 'Analyse du code', gravity: 'high', title: 'eval-detected', file: 'src/a.js', line: 3, blocks: true },
    { source: 'opengrep', control: 'Analyse du code', gravity: 'medium', title: 'weak-random', file: 'src/b.js', line: 9, blocks: false },
  ]
  const notes = [{ control: 'Vulnérabilités connues', title: 'Paquet interne : sapodata@3.2.0-SNAPSHOT', file: 'pom.xml' }]
  const text = markdown(result(findings, { notes, uncovered: ['Rust'] }))
  assert.match(text, /^# CI scan : \/tmp\/target$/m)
  assert.match(text, /^\*\*Décision : bloqué\*\* \(2 point\(s\) bloquant\(s\)\)$/m)
  assert.match(section(text, 'Technologies'), /^\| Rust \| \*\*Non couverte : bloque\*\* \|$/m)
  const counts = section(text, 'Résultats')
  assert.match(counts, /^\| Contrôle \| Critique \| Élevée \| Moyenne \| Faible \| Total \|$/m)
  assert.match(counts, /^\| Vulnérabilités connues \| 1 \|  \|  \|  \| 1 \|$/m)
  assert.match(counts, /^\| Analyse du code \|  \| 1 \| 1 \|  \| 2 \|$/m)
  const blocking = section(text, 'Points bloquants')
  assert.match(blocking, /^\| `package-lock.json` \| Vulnérabilités connues \| Critique \| lodash@4.17.21 CVE-2026-4800 \| osv \|$/m)
  assert.match(blocking, /^\| `src\/a.js:3` \| Analyse du code \| Élevée \| eval-detected \| opengrep \|$/m)
  assert.match(section(text, 'Signalé'), /^\| `src\/b.js:9` \| Analyse du code \| Moyenne \| weak-random \| opengrep \|$/m)
  assert.match(section(text, 'Pour information'), /^\| `pom.xml` \| Vulnérabilités connues \| Paquet interne : sapodata@3.2.0-SNAPSHOT \|$/m)
})

test('a | or a line break in a finding does not break the table', () => {
  const findings = [{ source: 'opengrep', control: 'Analyse du code', gravity: 'high', title: 'a | b\nc', file: 'x|y.js', blocks: true }]
  const text = markdown(result(findings))
  assert.match(section(text, 'Points bloquants'), /^\| `x\\\|y.js` \| Analyse du code \| Élevée \| a \\\| b c \| opengrep \|$/m)
})

test('a long table shows the first rows and counts the rest', () => {
  const findings = Array.from({ length: MAX_ROWS + 5 }, (_, index) => ({
    source: 'osv', control: 'Vulnérabilités connues', gravity: 'high', title: `flaw ${index}`, file: 'package-lock.json', blocks: true,
  }))
  const blocking = section(markdown(result(findings)), 'Points bloquants')
  assert.equal(blocking.split('\n').filter((line) => line.startsWith('| `package-lock.json`')).length, MAX_ROWS)
  assert.match(blocking, /^… et 5 autres : voir `ci-scan.sarif`\.$/m)
})

test('two tools that find the same flaw give one row, with the higher gravity', () => {
  const flaw = { control: 'Vulnérabilités connues', title: 'lodash@4.17.21 CVE-2026-4800', file: 'package-lock.json' }
  const findings = [
    { ...flaw, source: 'osv', gravity: 'high', blocks: true },
    { ...flaw, source: 'grype', gravity: 'critical', blocks: true },
    { ...flaw, source: 'grype', title: 'lodash@4.17.21 GHSA-xxxx', gravity: 'medium', blocks: false },
  ]
  const text = markdown(result(findings))
  assert.match(text, /^\*\*Décision : bloqué\*\* \(1 point\(s\) bloquant\(s\)\)$/m)
  assert.match(section(text, 'Résultats'), /^\| Vulnérabilités connues \| 1 \|  \| 1 \|  \| 2 \|$/m)
  const blocking = section(text, 'Points bloquants')
  assert.equal(blocking.split('\n').filter((line) => line.startsWith('| `package-lock.json`')).length, 1)
  assert.match(blocking, /^\| `package-lock.json` \| Vulnérabilités connues \| Critique \| lodash@4.17.21 CVE-2026-4800 \| osv, grype \|$/m)
  assert.match(section(text, 'Signalé'), /GHSA-xxxx \| grype \|$/m)
})
