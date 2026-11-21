/**
 * Minimal YAML subset parser for rule packs.
 *
 * Rule packs are data (strings, numbers, booleans, lists of maps). Supporting a
 * full YAML implementation would add a dependency to a plugin that deliberately
 * ships none, so this parser accepts exactly the shape the packs use:
 *
 *   schema: 1
 *   rules:
 *     - id: VG-CRED-01
 *       severity: blocker
 *       patterns:
 *         - re: '\\bAKIA[0-9A-Z]{16}\\b'
 *           label: AWS Access Key
 *
 * Supported: nested mappings, block sequences, single/double quoted scalars,
 * booleans, numbers, null, comments and `---` document markers. Not supported:
 * flow collections (`[a, b]`, `{a: b}`), anchors, multi-line block scalars.
 * Anything unsupported throws a `YamlParseError`, and the loader keeps the
 * built-in defaults instead of silently loading a half-parsed pack.
 *
 * @module rules/yaml
 */

export class YamlParseError extends Error {}

/**
 * @param {string} source
 * @returns {any}
 */
export function parseYaml(source) {
  const lines = []
  const rawLines = String(source ?? '').split(/\r?\n/)
  for (let index = 0; index < rawLines.length; index += 1) {
    const raw = rawLines[index]
    const trimmed = raw.trim()
    if (trimmed === '' || trimmed.startsWith('#')) continue
    if (trimmed === '---' || trimmed === '...') continue
    const indent = raw.length - raw.trimStart().length
    if (tabIndented(raw)) throw new YamlParseError(`第 ${index + 1} 行使用制表符缩进`)
    lines.push({ indent, text: trimmed, line: index + 1 })
  }
  let cursor = 0

  const peek = () => lines[cursor]

  const parseBlock = indent => {
    const first = peek()
    if (!first || first.indent < indent) return null
    return first.text.startsWith('-') ? parseSequence(first.indent) : parseMapping(first.indent)
  }

  const parseSequence = indent => {
    /** @type {any[]} */
    const out = []
    while (cursor < lines.length) {
      const line = lines[cursor]
      if (line.indent !== indent || !line.text.startsWith('-')) break
      if (line.text === '-' || line.text === '- ') {
        cursor += 1
        out.push(parseBlock(indent + 1))
        continue
      }
      const rest = line.text.slice(1).trim()
      const key = keyOf(rest)
      if (key === null) {
        cursor += 1
        out.push(parseScalar(rest, line.line))
        continue
      }
      // `- key: value` starts a mapping item; its remaining keys are indented.
      const item = {}
      const value = valueOf(rest)
      cursor += 1
      if (value === '') {
        const child = parseBlock(indent + 2)
        item[key] = child ?? null
      } else {
        item[key] = parseScalar(value, line.line)
      }
      while (cursor < lines.length && lines[cursor].indent > indent) {
        const nested = lines[cursor]
        if (nested.indent !== indent + 2) throw new YamlParseError(`第 ${nested.line} 行缩进不一致`)
        mergeMappingEntry(item, nested, () => {
          cursor += 1
          return parseBlock(indent + 2)
        })
      }
      out.push(item)
    }
    return out
  }

  const parseMapping = indent => {
    /** @type {Record<string, any>} */
    const out = {}
    while (cursor < lines.length && lines[cursor].indent === indent) {
      const line = lines[cursor]
      if (line.text.startsWith('-')) break
      const key = keyOf(line.text)
      if (key === null) throw new YamlParseError(`第 ${line.line} 行缺少 "key:"`)
      const value = valueOf(line.text)
      cursor += 1
      if (value === '') {
        const child = parseBlock(indent + 1)
        out[key] = child ?? null
      } else {
        out[key] = parseScalar(value, line.line)
      }
    }
    return out
  }

  const mergeMappingEntry = (target, line, advance) => {
    const key = keyOf(line.text)
    if (key === null) throw new YamlParseError(`第 ${line.line} 行缺少 "key:"`)
    const value = valueOf(line.text)
    if (value === '') {
      const child = advance()
      target[key] = child ?? null
    } else {
      advance()
      target[key] = parseScalar(value, line.line)
    }
  }

  const result = parseBlock(0)
  if (cursor < lines.length) throw new YamlParseError(`第 ${lines[cursor].line} 行无法解析`)
  return result
}

/** @param {string} raw */
function tabIndented(raw) {
  return /^\t/.test(raw) || /^ *\t/.test(raw)
}

/**
 * @param {string} text
 * @returns {string|null}
 */
function keyOf(text) {
  const match = /^([A-Za-z0-9_.-]+)\s*:(?:\s|$)/.exec(text)
  return match ? match[1] : null
}

/**
 * @param {string} text
 * @returns {string}
 */
function valueOf(text) {
  const index = text.indexOf(':')
  if (index < 0) return ''
  return text.slice(index + 1).trim()
}

/**
 * @param {string} value
 * @param {number} line
 * @returns {any}
 */
function parseScalar(value, line) {
  const text = value.trim()
  if (text === '') return ''
  if (text.startsWith('[') || text.startsWith('{')) {
    throw new YamlParseError(`第 ${line} 行不支持流式集合，请用缩进列表`)
  }
  if (text.startsWith("'")) {
    if (!text.endsWith("'") || text.length < 2) throw new YamlParseError(`第 ${line} 行单引号未闭合`)
    return text.slice(1, -1).replace(/''/g, "'")
  }
  if (text.startsWith('"')) {
    if (!text.endsWith('"') || text.length < 2) throw new YamlParseError(`第 ${line} 行双引号未闭合`)
    try {
      return JSON.parse(text)
    } catch {
      throw new YamlParseError(`第 ${line} 行双引号字符串转义无效`)
    }
  }
  if (text === 'true') return true
  if (text === 'false') return false
  if (text === 'null' || text === '~') return null
  if (/^-?\d+(?:\.\d+)?$/.test(text)) return Number(text)
  return text
}
