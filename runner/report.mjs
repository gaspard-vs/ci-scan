// The report of a scan as text. The page for the manager comes later.

function where(finding) {
  if (!finding.file) return ''
  return finding.line ? `${finding.file}:${finding.line} — ` : `${finding.file} — `
}

function list(names) {
  return names.length ? names.join(', ') : 'aucune'
}

export function text(result) {
  const lines = [
    `CI scan : ${result.repo}`,
    '',
    `Fichiers détectés : ${result.files}`,
    `Technologies couvertes : ${list(result.technologies)}`,
    `Technologies non couvertes : ${list(result.uncovered)}`,
    '',
    'Étapes :',
  ]
  for (const step of result.steps) {
    const outcome = step.count === null ? "n'a pas pu tourner" : `${step.count} résultat(s)`
    lines.push(`  ${step.id} (${step.control}) : ${outcome}`)
    if (step.summary) lines.push(`    ${step.summary}`)
    for (const name of step.outputs ?? []) lines.push(`    fichier : ${name}`)
    for (const data of step.data ?? []) {
      lines.push(`    données : ${data.file}, du ${data.date ? data.date.slice(0, 16).replace('T', ' ') + ' UTC' : '(date inconnue)'}`)
    }
    if (step.requests) {
      const { total, refused } = step.requests
      lines.push(`    requêtes vers l'extérieur : ${total}, dont ${refused} refusée(s)`)
    }
  }
  const blocking = result.findings.filter((finding) => finding.blocks)
  const reported = result.findings.filter((finding) => !finding.blocks)
  const groups = [
    ['Points bloquants', blocking],
    ['Signalé', reported],
    ['Pour information', result.notes ?? []],
  ]
  for (const [title, group] of groups) {
    if (!group.length) continue
    lines.push('', `${title} :`)
    for (const finding of group) {
      lines.push(`  [${finding.control}] ${where(finding)}${finding.title}`)
    }
  }
  lines.push('', `Décision : ${result.verdict.toUpperCase()}`)
  return lines.join('\n')
}

// GitHub shows these lines on the pull request, at the file and the line.
const escapeData = (value) =>
  String(value).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A')
const escapeProperty = (value) => escapeData(value).replace(/:/g, '%3A').replace(/,/g, '%2C')

export function annotations(result) {
  return result.findings
    .filter((finding) => finding.blocks)
    .map((finding) => {
      const properties = []
      if (finding.file) properties.push(`file=${escapeProperty(finding.file)}`)
      if (finding.line) properties.push(`line=${finding.line}`)
      const head = properties.length ? `::error ${properties.join(',')}` : '::error'
      return `${head}::${escapeData(`[${finding.control}] ${finding.title}`)}`
    })
    .join('\n')
}
