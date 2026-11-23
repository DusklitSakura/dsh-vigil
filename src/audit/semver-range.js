import { compareVersions, parseVersion } from './dsh-version.js'

/** @typedef {{ major: number, minor: number, patch: number, prerelease: string[] }} ParsedVersion */
/**
 * Plain semver range matching for `engines.node`.
 *
 * `satisfiesDshRange` is deliberately conservative for DSH hijack checks: it
 * answers "unknown" whenever a comparator is involved. `engines.node` needs the
 * real answer, so this helper implements the common npm forms (exact, `=`,
 * `>`, `>=`, `<`, `<=`, `^`, `~`, `x`-ranges, hyphen ranges, `||`) and returns
 * "unknown" only when a token cannot be parsed.
 *
 * @param {string} spec
 * @param {string} version
 * @returns {'satisfied'|'unsatisfied'|'unknown'}
 */
export function satisfiesSemverRange(spec, version) {
  const parsedVersion = parseVersion(version)
  if (!parsedVersion || typeof spec !== 'string' || spec.trim() === '') return 'unknown'
  const clauses = spec.split('||').map(part => part.trim()).filter(Boolean)
  if (clauses.length === 0) return 'unknown'
  let unknown = false
  for (const clause of clauses) {
    const verdict = satisfiesClause(clause, parsedVersion)
    if (verdict === 'satisfied') return 'satisfied'
    if (verdict === 'unknown') unknown = true
  }
  return unknown ? 'unknown' : 'unsatisfied'
}

/** @param {string} clause @param {ParsedVersion} version */
function satisfiesClause(clause, version) {
  const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(clause)
  if (hyphen) {
    const lower = satisfiesToken(`>=${hyphen[1]}`, version)
    const upper = upperBoundVerdict(hyphen[2], version)
    if (lower === 'unknown' || upper === 'unknown') return 'unknown'
    return lower === 'satisfied' && upper === 'satisfied' ? 'satisfied' : 'unsatisfied'
  }
  for (const token of clause.split(/\s+/).filter(Boolean)) {
    const verdict = satisfiesToken(token, version)
    if (verdict !== 'satisfied') return verdict
  }
  return 'satisfied'
}

/** @param {string} token @param {ParsedVersion} version */
function satisfiesToken(token, version) {
  const match = /^(<=|>=|<|>|=|\^|~)?\s*v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?(?:-([0-9A-Za-z.-]+))?$/.exec(token)
  if (!match) return 'unknown'
  const operator = match[1] ?? ''
  const major = Number(match[2])
  const minorToken = match[3]
  const patchToken = match[4]
  const wildcardMinor = minorToken === undefined || minorToken === 'x' || minorToken === '*'
  const wildcardPatch = patchToken === undefined || patchToken === 'x' || patchToken === '*'
  const minor = wildcardMinor ? 0 : Number(minorToken)
  const patch = wildcardPatch ? 0 : Number(patchToken)
  const prerelease = match[5] ?? ''
  const bound = parseVersion(`${major}.${minor}.${patch}${prerelease ? `-${prerelease}` : ''}`)
  if (!bound || !Number.isFinite(major) || !Number.isFinite(minor) || !Number.isFinite(patch)) return 'unknown'

  if (operator === '^') {
    const upTo = major > 0
      ? parseVersion(`${major + 1}.0.0-0`)
      : (minor > 0 ? parseVersion(`0.${minor + 1}.0-0`) : parseVersion(`0.0.${patch + 1}-0`))
    const low = compareVersions(version, bound) >= 0
    const high = upTo !== null && compareVersions(version, upTo) < 0
    return low && high ? 'satisfied' : 'unsatisfied'
  }
  if (operator === '~') {
    const upTo = wildcardMinor ? parseVersion(`${major + 1}.0.0-0`) : parseVersion(`${major}.${minor + 1}.0-0`)
    const low = compareVersions(version, bound) >= 0
    const high = upTo !== null && compareVersions(version, upTo) < 0
    return low && high ? 'satisfied' : 'unsatisfied'
  }
  if (operator === '' || operator === '=') {
    if (wildcardMinor) return version.major === major ? 'satisfied' : 'unsatisfied'
    if (wildcardPatch) return version.major === major && version.minor === minor ? 'satisfied' : 'unsatisfied'
    return compareVersions(version, bound) === 0 ? 'satisfied' : 'unsatisfied'
  }
  return comparatorVerdict(operator, `${major}.${minor}.${patch}${prerelease ? `-${prerelease}` : ''}`, version)
}

/** @param {string} operator @param {string} spec @param {ParsedVersion} version */
function comparatorVerdict(operator, spec, version) {
  const bound = parseVersion(spec)
  if (!bound) return 'unknown'
  const order = compareVersions(version, bound)
  switch (operator) {
    case '>': return order > 0 ? 'satisfied' : 'unsatisfied'
    case '>=': return order >= 0 ? 'satisfied' : 'unsatisfied'
    case '<': return order < 0 ? 'satisfied' : 'unsatisfied'
    case '<=': return order <= 0 ? 'satisfied' : 'unsatisfied'
    default: return 'unknown'
  }
}
/**
 * Upper end of a hyphen range. A partial bound (`16`) means "through 16.x",
 * so the real upper limit is the next major with an exclusive comparison.
 * @param {string} spec
 * @param {ParsedVersion} version
 * @returns {'satisfied'|'unsatisfied'|'unknown'}
 */
function upperBoundVerdict(spec, version) {
  const match = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-[0-9A-Za-z.-]+)?$/.exec(spec)
  if (!match) return 'unknown'
  const major = Number(match[1])
  const minor = match[2] === undefined ? null : Number(match[2])
  const patch = match[3] === undefined ? null : Number(match[3])
  const bound = patch !== null
    ? parseVersion(`${major}.${minor}.${patch}`)
    : (minor !== null ? parseVersion(`${major}.${minor + 1}.0-0`) : parseVersion(`${major + 1}.0.0-0`))
  if (!bound) return 'unknown'
  const exclusive = patch === null
  const order = compareVersions(version, bound)
  return (exclusive ? order < 0 : order <= 0) ? 'satisfied' : 'unsatisfied'
}