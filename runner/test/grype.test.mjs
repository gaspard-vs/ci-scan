// The Grype stage: the tests of our Python program, in its image, its stage
// file and its image.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { readStages, readStep } from '../steps.mjs'
import { unittest } from './python.mjs'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const GRYPE = path.join(ROOT, 'common', '32-deps-grype')

const docker = spawnSync('docker', ['info'], { stdio: 'ignore' }).status === 0
const skip = !docker && !process.env.CI ? 'Docker does not run' : false

test('grype_sarif.py passes its tests', { skip }, () => unittest(GRYPE, '32-deps-grype'))

test('the Grype stage reads the SBOM of an earlier stage, with no network', async () => {
  const stages = await readStages(path.join(ROOT, 'common'))
  const grype = stages.findIndex((stage) => stage.id === 'grype')
  const syft = stages.findIndex((stage) => stage.id === 'syft')
  assert.ok(syft >= 0 && syft < grype)
  const stage = stages[grype]
  assert.equal(stage.input, 'sbom.cdx.json')
  assert.equal(stage.network, undefined)
  assert.equal(stage.proxy, undefined)
})

test('the Grype stage prepares the database that it reads', async () => {
  const stage = await readStep(GRYPE, 'stage.json', { stage: true })
  const program = await readFile(path.join(GRYPE, 'grype_sarif.py'), 'utf8')
  const [data] = stage.data
  assert.match(program, new RegExp(`ARCHIVE = "/data/${data.file}"\n`))
  assert.match(program, new RegExp(`PREPARED = "/data/${stage.prepare.folder}"\n`))
  assert.match(data.listing, /^https:\/\/grype\.anchore\.io\/databases\/v6\/latest\.json$/)
})

test('the image of the Grype stage has fixed bases', async () => {
  const stage = await readStep(GRYPE, 'stage.json', { stage: true })
  const dockerfile = await readFile(path.join(GRYPE, 'Dockerfile'), 'utf8')
  const bases = dockerfile.split('\n').filter((line) => line.startsWith('FROM '))
  assert.equal(bases.length, 2)
  for (const base of bases) assert.match(base, /@sha256:[0-9a-f]{64}( |$)/)
  assert.match(dockerfile, new RegExp(`anchore/grype:${stage.version}\n`))
  const osv = await readFile(path.join(ROOT, 'common', '30-deps-osv', 'Dockerfile'), 'utf8')
  assert.equal(bases[1], osv.split('\n').filter((line) => line.startsWith('FROM '))[1])
})
