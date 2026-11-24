// The report of a scan as text. The page for the manager comes later.

function where(finding) {
  if (!finding.file) return ''
  return finding.line ? `${finding.file}:${finding.line} — ` : `${finding.file} — `
}

function list(names) {
  return names.length ? names.join(', ') : 'aucune'
}

// A covered technology with no stage of its own says so.
function covered(result) {
  if (!result.coverage) return list(result.technologies)
  return list(result.coverage.map((tech) => (tech.commonOnly ? `${tech.label} (contrôles communs seulement)` : tech.label)))
}

export function text(result) {
  const lines = [
    `CI scan : ${result.repo}`,
    '',
    `Fichiers détectés : ${result.files}`,
    `Technologies couvertes : ${covered(result)}`,
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

// The report for people, in French: rapport.md. GitHub tables only, so that
// GitHub shows it as the summary of the run.

const GRAVITIES = [
  ['critical', 'Critique'],
  ['high', 'Élevée'],
  ['medium', 'Moyenne'],
  ['low', 'Faible'],
]

// A table shows this many rows at most. The rest is counted.
export const MAX_ROWS = 200

// A value in a table cell: no line break, and a | does not end the cell.
const cell = (value) => String(value ?? '').replace(/\r?\n/g, ' ').replace(/\\/g, '\\\\').replace(/\|/g, '\\|')
const code = (value) => (value ? `\`${String(value).replace(/`/g, "'")}\`` : '')
const gravityName = (gravity) => GRAVITIES.find(([id]) => id === gravity)?.[1] ?? gravity ?? ''

function table(head, rows) {
  const lines = [`| ${head.join(' | ')} |`, `| ${head.map(() => '---').join(' | ')} |`]
  for (const row of rows.slice(0, MAX_ROWS)) lines.push(`| ${row.map(cell).join(' | ')} |`)
  if (rows.length > MAX_ROWS) lines.push('', `… et ${rows.length - MAX_ROWS} autres : voir \`ci-scan.sarif\`.`)
  return lines
}

const place = (finding) => code(finding.file ? (finding.line ? `${finding.file}:${finding.line}` : finding.file) : '')

// Two tools that find the same flaw (same file, line and name) give one row,
// with both tools. The higher gravity wins. The SARIF keeps both results.
const rank = (gravity) => {
  const index = GRAVITIES.findIndex(([id]) => id === gravity)
  return index === -1 ? GRAVITIES.length : index
}

export function flaws(findings) {
  const byKey = new Map()
  for (const finding of findings) {
    const key = JSON.stringify([finding.file ?? '', finding.line ?? '', finding.title])
    const known = byKey.get(key)
    if (!known) {
      byKey.set(key, { ...finding, sources: [finding.source] })
      continue
    }
    if (!known.sources.includes(finding.source)) known.sources.push(finding.source)
    if (rank(finding.gravity) < rank(known.gravity)) {
      known.gravity = finding.gravity
      known.control = finding.control
    }
    known.blocks = known.blocks || finding.blocks
  }
  return [...byKey.values()]
}

//   options.name: the name of the repository; options.date: the time of the scan
export function markdown(result, { name, date } = {}) {
  const found = flaws(result.findings)
  const blocking = found.filter((finding) => finding.blocks)
  const reported = found.filter((finding) => !finding.blocks)
  const lines = [`# CI scan : ${name ?? result.repo}`, '']
  if (date) lines.push(`Scan du ${date.toISOString().slice(0, 16).replace('T', ' ')} UTC.`, '')
  lines.push(
    result.verdict === 'conforme' ? '**Décision : conforme**' : `**Décision : bloqué** (${blocking.length} point(s) bloquant(s))`,
    '',
    '## Technologies',
    '',
  )
  const technologies = (result.coverage ?? result.technologies.map((id) => ({ label: id }))).map((tech) => [
    tech.label,
    tech.commonOnly ? 'Couverte : contrôles communs seulement' : 'Couverte',
  ])
  for (const language of result.uncovered) technologies.push([language, '**Non couverte : bloque**'])
  if (technologies.length) lines.push(...table(['Technologie', 'État'], technologies))
  else lines.push('Aucune technologie détectée.')
  lines.push('', `${result.files} fichier(s) détecté(s).`)

  // The number of flaws, by control and by gravity.
  if (found.length) {
    const controls = [...new Set(found.map((finding) => finding.control))]
    const rows = controls.map((control) => {
      const mine = found.filter((finding) => finding.control === control)
      return [control, ...GRAVITIES.map(([id]) => mine.filter((finding) => finding.gravity === id).length || ''), mine.length]
    })
    lines.push('', '## Résultats', '', ...table(['Contrôle', ...GRAVITIES.map(([, label]) => label), 'Total'], rows))
  }

  const groups = [
    ['Points bloquants', blocking, true],
    ['Signalé', reported, true],
    ['Pour information', result.notes ?? [], false],
  ]
  for (const [title, group, withGravity] of groups) {
    if (!group.length) continue
    const head = withGravity
      ? ['Fichier', 'Contrôle', 'Gravité', 'Résultat', 'Trouvé par']
      : ['Fichier', 'Contrôle', 'Résultat']
    const rows = group.map((finding) =>
      withGravity
        ? [place(finding), finding.control, gravityName(finding.gravity), finding.title, finding.sources.join(', ')]
        : [place(finding), finding.control, finding.title],
    )
    lines.push('', `## ${title}`, '', ...table(head, rows))
  }

  const steps = result.steps.map((step) => {
    const details = []
    if (step.summary) details.push(step.summary)
    for (const output of step.outputs ?? []) details.push(`fichier ${code(output)}`)
    for (const data of step.data ?? []) {
      details.push(`données du ${data.date ? data.date.slice(0, 16).replace('T', ' ') + ' UTC' : '(date inconnue)'}`)
    }
    if (step.requests) details.push(`${step.requests.total} requête(s) vers l'extérieur, ${step.requests.refused} refusée(s)`)
    const outcome = step.count === null ? "N'a pas pu tourner" : String(step.count)
    return [`${step.control} (${step.id})`, outcome, details.join(' ; ')]
  })
  lines.push('', '## Étapes', '', ...table(['Étape', 'Résultats', 'Détail'], steps))
  lines.push('', 'Le détail technique est dans `ci-scan.sarif`.', '')
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
