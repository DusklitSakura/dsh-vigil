/**
 * Shared lexical primitives for the three shell deletion parsers.
 *
 * The parsers used to define the same sentinel, token cap, unmask and basename
 * helpers independently; a divergence there changes what counts as a delete
 * target on only one shell. Keep the primitives here.
 *
 * @module delete/lex
 */

/** Sentinel protecting literal characters from variable/glob expansion. */
export const ESC = '\u0001'

/** Hard cap on tokens per simple command (pathological input defence). */
export const MAX_TOKENS = 2048

/**
 * Decode masked text (`\u0001$` -> `$`).
 * @param {string} value
 * @returns {string}
 */
export function unmask(value) {
  return typeof value === 'string' && value.indexOf(ESC) >= 0 ? value.split(ESC).join('') : String(value || '')
}

/**
 * Lowercase basename of a command word without stripping a call operator.
 * Handles `/usr/bin/rm` and `C:\tools\rm.exe`.
 * @param {string} value
 * @returns {string}
 */
export function baseName(value) {
  const text = unmask(value).trim()
  const idx = Math.max(text.lastIndexOf('/'), text.lastIndexOf('\\'))
  return (idx >= 0 ? text.slice(idx + 1) : text).replace(/\.exe$/i, '').toLowerCase()
}

/**
 * PowerShell command word: like {@link baseName}, but also strips a leading
 * call operator (`& 'rm'`).
 * @param {string} value
 * @returns {string}
 */
export function commandName(value) {
  return baseName(String(value || '').replace(/^\s*&/, ''))
}
