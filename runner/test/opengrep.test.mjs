// The Opengrep stage: our own rules and their tests, the copy of the GitLab
// rules, and the gravities that the stage sets.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { launch } from '../docker.mjs'
import { readStep } from '../steps.mjs'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const STAGE = path.join(ROOT, 'common', '20-code-opengrep')

const docker = spawnSync('docker', ['info'], { stdio: 'ignore' }).status === 0
const skip = !docker && !process.env.CI ? 'Docker does not run' : false

async function filesOf(dir) {
  const entries = await readdir(dir, { recursive: true, withFileTypes: true })
  return entries.filter((entry) => entry.isFile()).map((entry) => path.join(entry.parentPath, entry.name))
}

// The ids of all the rules of the stage, as Opengrep names them: the folder
// of the rule file under /stage, with dots, then the id.
async function ruleIds() {
  const ids = new Set()
  for (const file of await filesOf(STAGE)) {
    if (!file.endsWith('.yml')) continue
    const prefix = ['stage', ...path.relative(STAGE, path.dirname(file)).split(path.sep)].join('.')
    for (const [, id] of (await readFile(file, 'utf8')).matchAll(/^\s*-\s+id:\s*"?([^"\s]+)"?\s*$/gm)) {
      ids.add(`${prefix}.${id}`)
    }
  }
  return ids
}

test('each of our rules has a test file with a match and a non-match', async () => {
  const dir = path.join(STAGE, 'rules')
  const names = await readdir(dir)
  const rules = names.filter((name) => name.endsWith('.yml'))
  assert.ok(rules.length > 0)
  for (const rule of rules) {
    const stem = rule.slice(0, -'.yml'.length)
    const tests = names.filter((name) => name !== rule && name.startsWith(`${stem}.`))
    assert.equal(tests.length, 1, `${rule}: one test file ${stem}.<ext>`)
    const content = await readFile(path.join(dir, tests[0]), 'utf8')
    assert.match(content, new RegExp(`ruleid: ${stem}\\b`), `${tests[0]}: no line that must match`)
    assert.match(content, new RegExp(`ok: ${stem}\\b`), `${tests[0]}: no line that must not match`)
  }
})

test('our rules pass their tests in Opengrep', { skip }, async () => {
  const stage = await readStep(STAGE, 'stage.json', { stage: true })
  const args = ['scan', '--test', '--disable-version-check', '/stage/rules']
  const result = await launch({ ...stage, args }, path.join(ROOT, 'fixtures', 'clean'), { timeout: 600_000 })
  assert.equal(result.code, 0, result.stdout + result.stderr)
  assert.match(result.stdout + result.stderr, /All tests passed/)
})

test('each gravity that the stage sets is for a rule of the stage', async () => {
  const stage = await readStep(STAGE, 'stage.json', { stage: true })
  const ids = await ruleIds()
  for (const id of Object.keys(stage.gravities)) assert.ok(ids.has(id), `no rule ${id}`)
})

test('the copy of the GitLab rules names its commit and holds no closed rule', async () => {
  const dir = path.join(STAGE, 'gitlab')
  const source = JSON.parse(await readFile(path.join(dir, 'SOURCE.json'), 'utf8'))
  assert.match(source.commit, /^[0-9a-f]{40}$/)
  const files = (await filesOf(dir)).map((file) => path.relative(dir, file))
  const rules = files.filter((file) => file.endsWith('.yml'))
  assert.equal(rules.length, source.rules)
  assert.deepEqual(rules.filter((file) => /^rules\/(?!lgpl\/)/.test(file)), [])
  assert.ok(files.includes('LICENSE') && files.includes('rules/lgpl/LICENSE'))
})
