#!/usr/bin/env node
// CI scan: scans one repository and gives the verdict.
//
//   node runner/cli.mjs <repository> [--out <folder>]
//
// --out receives ci-scan.sarif and the files that the stages give
// (sbom.cdx.json).
//
// Exit code: 0 conforme, 1 bloqué, 2 the scan itself failed.
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { parseArgs } from 'node:util'
import { annotations, text } from './report.mjs'
import { run } from './run.mjs'

async function main() {
  const { values, positionals } = parseArgs({
    options: { out: { type: 'string' } },
    allowPositionals: true,
  })
  if (positionals.length !== 1) {
    console.error('usage: node runner/cli.mjs <repository> [--out <folder>]')
    return 2
  }
  const result = await run(positionals[0])
  console.log(text(result))
  if (process.env.GITHUB_ACTIONS) {
    const lines = annotations(result)
    if (lines) console.log(lines)
  }
  if (values.out) {
    await mkdir(values.out, { recursive: true })
    await writeFile(path.join(values.out, 'ci-scan.sarif'), JSON.stringify(result.sarif, null, 1))
    // The files that the stages give, such as the SBOM.
    for (const { name, content } of result.outputs) {
      await writeFile(path.join(values.out, name), typeof content === 'string' ? content : JSON.stringify(content))
    }
  }
  return result.verdict === 'conforme' ? 0 : 1
}

main().then(
  (code) => {
    process.exitCode = code
  },
  (error) => {
    console.error(`CI scan a échoué : ${error.message}`)
    process.exitCode = 2
  },
)
