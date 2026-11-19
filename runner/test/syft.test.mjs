// The Syft stage: the tests of our Python program, in its image, its stage
// file and its settings.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { readStep } from '../steps.mjs'
import { unittest } from './python.mjs'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const SYFT = path.join(ROOT, 'common', '05-sbom-syft')
const MAVEN = path.join(ROOT, 'common', '31-deps-maven')

const docker = spawnSync('docker', ['info'], { stdio: 'ignore' }).status === 0
const skip = !docker && !process.env.CI ? 'Docker does not run' : false

test('sbom_sarif.py passes its tests', { skip }, () => unittest(SYFT, '05-sbom-syft'))

test('the Syft stage goes out only through the Maven helper, with the same settings as OSV', async () => {
  const stage = await readStep(SYFT, 'stage.json', { stage: true })
  const maven = await readStep(MAVEN, 'stage.json', { stage: true })
  assert.equal(stage.network, undefined)
  assert.equal(path.resolve(SYFT, stage.proxy.build), path.join(MAVEN, 'helper'))
  assert.deepEqual(stage.proxy.args, maven.proxy.args)
  const settings = await readFile(path.join(SYFT, 'syft.yaml'), 'utf8')
  assert.match(settings, /maven-url: http:\/\/proxy:8080\/maven2\n/)
  assert.match(settings, /resolve-transitive-dependencies: false\n/)
})

test('the image of the Syft stage has fixed bases', async () => {
  const stage = await readStep(SYFT, 'stage.json', { stage: true })
  const dockerfile = await readFile(path.join(SYFT, 'Dockerfile'), 'utf8')
  const bases = dockerfile.split('\n').filter((line) => line.startsWith('FROM '))
  assert.equal(bases.length, 2)
  for (const base of bases) assert.match(base, /@sha256:[0-9a-f]{64}( |$)/)
  assert.match(dockerfile, new RegExp(`anchore/syft:${stage.version}\n`))
})
