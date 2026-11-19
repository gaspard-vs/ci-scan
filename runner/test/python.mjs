// The Python programs of the stages: their tests run in the image of the
// stage, with no network.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { buildImage } from '../docker.mjs'

// Runs the Python tests of a folder in an image, with no network.
export async function unittest(dir, name) {
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
