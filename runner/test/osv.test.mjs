// The OSV stages: the tests of our Python programs, in their images, and
// the agreement between the two stage files.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import path from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { buildImage } from '../docker.mjs'
import { readStep } from '../steps.mjs'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const OSV = path.join(ROOT, 'common', '30-deps-osv')
const MAVEN = path.join(ROOT, 'common', '31-deps-maven')
const HELPER = path.join(MAVEN, 'helper')

const docker = spawnSync('docker', ['info'], { stdio: 'ignore' }).status === 0
const skip = !docker && !process.env.CI ? 'Docker does not run' : false

// Runs the Python tests of a folder in an image, with no network.
async function unittest(dir, name) {
  const { image, error } = await buildImage(dir, name)
  assert.equal(error, undefined, error)
  const result = spawnSync(
    'docker',
    [
      'run', '--rm', '--read-only', '--network', 'none', '--tmpfs', '/tmp',
      '--volume', `${dir}:/stage:ro`,
      '--entrypoint', 'python', image,
      '-I', '-m', 'unittest', 'discover', '-s', '/stage', '-p', 'test_*.py',
    ],
    { encoding: 'utf8' },
  )
  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stderr, /\nOK\n/)
}

test('osv_sarif.py passes its tests', { skip }, () => unittest(OSV, '30-deps-osv'))

test('the helper passes its tests', { skip }, () => unittest(HELPER, 'osv-maven-proxy'))

test('the Maven stage asks its proxy, and both know the same internal packages', async () => {
  const stage = await readStep(MAVEN, 'stage.json', { stage: true })
  const value = (args, flag) => args.filter((_, i) => args[i - 1] === flag)
  assert.deepEqual(value(stage.args, '--registry'), ['http://proxy:8080/maven2'])
  assert.deepEqual(value(stage.args, '--internal'), value(stage.proxy.args, '--internal'))
  assert.deepEqual(value(stage.proxy.args, '--upstream'), ['https://repo.maven.apache.org/maven2'])
  assert.equal(path.resolve(MAVEN, stage.build), OSV)
})

test('the lock files stage leaves pom.xml to the Maven stage', async () => {
  const stage = await readStep(OSV, 'stage.json', { stage: true })
  const names = stage.data.flatMap((entry) => entry.when)
  assert.ok(!names.includes('pom.xml'))
  assert.ok(names.includes('package-lock.json'))
})
