// The detection: each file of the repository must have an owner. The owner is a
// technology that CI scan covers, or a kind of file listed in the policy.
import { readdir } from 'node:fs/promises'
import path from 'node:path'

// All the files of the repository, as the runner sees them. The detection of
// the container must name each of them.
export async function listFiles(repo) {
  const files = []
  const walk = async (dir, prefix) => {
    const entries = await readdir(dir, { withFileTypes: true })
    for (const entry of entries) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name
      if (entry.isDirectory()) {
        if (rel !== '.git') await walk(path.join(dir, entry.name), rel)
      } else {
        files.push(rel)
      }
    }
  }
  await walk(repo, '')
  return files.sort()
}

// The output of the detection container: one JSON line per file.
export function parseDetection(stdout) {
  const entries = new Map()
  for (const line of stdout.split('\n')) {
    if (!line.trim()) continue
    const entry = JSON.parse(line)
    if (typeof entry.path !== 'string') throw new Error('a detection line has no path')
    entries.set(entry.path, entry)
  }
  return entries
}

// Gives each file its owner.
//   technologies: the names of the covered technologies found in the repository
//   uncovered:    language -> files, for the languages that nobody owns
//   unowned:      files that the detection cannot name, with the reason
export function assign(files, entries, policy, technologies) {
  const byLanguage = new Map()
  for (const tech of technologies) {
    for (const language of tech.languages) byLanguage.set(language, tech.name)
  }
  const inert = new Set(policy.inert.languages)
  const inertMimes = new Set(policy.inert.mimes)
  const configuration = new Set(policy.configuration.languages)

  const found = new Set()
  const uncovered = new Map()
  const unowned = []

  for (const file of files) {
    const entry = entries.get(file)
    if (!entry) {
      unowned.push({ file, reason: 'absent de la détection' })
    } else if (entry.link) {
      unowned.push({ file, reason: 'lien symbolique' })
    } else if (entry.language) {
      const language = entry.language
      if (byLanguage.has(language)) found.add(byLanguage.get(language))
      else if (!inert.has(language) && !configuration.has(language)) {
        if (!uncovered.has(language)) uncovered.set(language, [])
        uncovered.get(language).push(file)
      }
    } else if (!(entry.binary && inertMimes.has(entry.mime))) {
      unowned.push({ file, reason: entry.binary ? 'binaire de type inconnu' : 'type de fichier inconnu' })
    }
  }
  return { technologies: [...found].sort(), uncovered, unowned }
}
